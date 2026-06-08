require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const axios = require('axios');
const crypto = require('crypto');
const multer = require('multer');

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
    cors: { origin: '*', methods: ['GET', 'POST'] }
});

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const storage = multer.memoryStorage();
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });

app.use((req, res, next) => {
    req.io = io;
    req.pool = pool;
    next();
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token no proporcionado' });
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(403).json({ error: 'Token inválido o expirado' });
    }
}

function requireRole(role) {
    return (req, res, next) => {
        if (req.user.role !== role) {
            return res.status(403).json({ error: `Se requiere rol de ${role}` });
        }
        next();
    };
}

app.get('/', (req, res) => {
    res.json({
        message: '🏍️ MotoApp Jamundí API',
        version: '1.0.0',
        status: 'online',
        timestamp: new Date().toISOString()
    });
});

app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, phone, password, role } = req.body;
        if (!name || !phone || !password || !role) {
            return res.status(400).json({ error: 'Todos los campos son obligatorios' });
        }
        if (!['PASSENGER', 'DRIVER'].includes(role)) {
            return res.status(400).json({ error: 'Rol inválido' });
        }
        const existing = await pool.query('SELECT id FROM users WHERE phone = $1', [phone]);
        if (existing.rows.length > 0) {
            return res.status(400).json({ error: 'Este teléfono ya está registrado' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const userResult = await pool.query(
            `INSERT INTO users (name, phone, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id, name, phone, role`,
            [name, phone, hashedPassword, role]
        );
        const user = userResult.rows[0];
        if (role === 'DRIVER') {
            await pool.query('INSERT INTO drivers (user_id) VALUES ($1)', [user.id]);
            await pool.query('INSERT INTO driver_tokens (driver_id, balance) VALUES ($1, 0)', [user.id]);
        }
        const token = jwt.sign({ id: user.id, role: user.role, name: user.name }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN });
        res.status(201).json({ success: true, token, user });
    } catch (error) {
        console.error('Error en registro:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { phone, password } = req.body;
        if (!phone || !password) return res.status(400).json({ error: 'Teléfono y contraseña son obligatorios' });
        const result = await pool.query('SELECT id, name, phone, role, password_hash FROM users WHERE phone = $1', [phone]);
        if (result.rows.length === 0) return res.status(401).json({ error: 'Credenciales inválidas' });
        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) return res.status(401).json({ error: 'Credenciales inválidas' });
        const token = jwt.sign({ id: user.id, role: user.role, name: user.name }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN });
        res.json({ success: true, token, user: { id: user.id, name: user.name, phone: user.phone, role: user.role } });
    } catch (error) {
        console.error('Error en login:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

app.get('/api/zones', async (req, res) => {
    try {
        const result = await pool.query('SELECT id, name, zone_type, base_fare, per_km_fare, polygon_coords FROM zones ORDER BY name');
        res.json({ success: true, zones: result.rows });
    } catch (error) {
        res.status(500).json({ error: 'Error al obtener zonas' });
    }
});

app.get('/api/pois', async (req, res) => {
    try {
        const { category } = req.query;
        let query = 'SELECT * FROM pois';
        const params = [];
        if (category) {
            params.push(category);
            query += ' WHERE category = $1';
        }
        query += ' ORDER BY name';
        const result = await pool.query(query, params);
        res.json({ success: true, pois: result.rows });
    } catch (error) {
        res.status(500).json({ error: 'Error al obtener POIs' });
    }
});

app.post('/api/rides/request', authenticateToken, requireRole('PASSENGER'), async (req, res) => {
    try {
        const { origin_lat, origin_lng, dest_lat, dest_lng, origin_name, dest_name } = req.body;
        if (!origin_lat || !origin_lng || !dest_lat || !dest_lng) {
            return res.status(400).json({ error: 'Coordenadas obligatorias' });
        }
        const result = await pool.query(
            `INSERT INTO rides (passenger_id, origin_lat, origin_lng, dest_lat, dest_lng, status) VALUES ($1, $2, $3, $4, $5, 'REQUESTED') RETURNING *`,
            [req.user.id, origin_lat, origin_lng, dest_lat, dest_lng]
        );
        const ride = result.rows[0];
        req.io.to('drivers_online').emit('new_ride_request', {
            rideId: ride.id,
            origin: { lat: origin_lat, lng: origin_lng, name: origin_name },
            destination: { lat: dest_lat, lng: dest_lng, name: dest_name },
            passengerName: req.user.name
        });
        res.status(201).json({ success: true, ride });
    } catch (error) {
        console.error('Error al solicitar viaje:', error);
        res.status(500).json({ error: 'Error al crear viaje' });
    }
});

app.post('/api/rides/:rideId/accept', authenticateToken, requireRole('DRIVER'), async (req, res) => {
    try {
        const { rideId } = req.params;
        const driverCheck = await pool.query('SELECT is_approved FROM drivers WHERE user_id = $1', [req.user.id]);
        if (!driverCheck.rows[0]?.is_approved) {
            return res.status(403).json({ error: 'Tu cuenta aún no está aprobada' });
        }
        const result = await pool.query(
            `UPDATE rides SET driver_id = $1, status = 'ACCEPTED' WHERE id = $2 AND status = 'REQUESTED' RETURNING *`,
            [req.user.id, rideId]
        );
        if (result.rows.length === 0) return res.status(400).json({ error: 'El viaje ya no está disponible' });
        const passenger = await pool.query('SELECT passenger_id FROM rides WHERE id = $1', [rideId]);
        req.io.to(`user_${passenger.rows[0].passenger_id}`).emit('ride_accepted', {
            rideId, driverId: req.user.id, driverName: req.user.name
        });
        res.json({ success: true, ride: result.rows[0] });
    } catch (error) {
        res.status(500).json({ error: 'Error al aceptar viaje' });
    }
});

app.get('/api/tokens/balance', authenticateToken, requireRole('DRIVER'), async (req, res) => {
    try {
        const result = await pool.query('SELECT balance, is_boosted FROM driver_tokens WHERE driver_id = $1', [req.user.id]);
        if (result.rows.length === 0) return res.json({ balance: 0, is_boosted: false });
        res.json({ success: true, ...result.rows[0] });
    } catch (error) {
        res.status(500).json({ error: 'Error al obtener saldo' });
    }
});

app.post('/api/tokens/toggle-boost', authenticateToken, requireRole('DRIVER'), async (req, res) => {
    try {
        const tokenData = await pool.query('SELECT balance, is_boosted FROM driver_tokens WHERE driver_id = $1', [req.user.id]);
        if (tokenData.rows.length === 0 || tokenData.rows[0].balance === 0) {
            return res.status(400).json({ error: 'No tienes tokens suficientes' });
        }
        const newBoostState = !tokenData.rows[0].is_boosted;
        await pool.query(`UPDATE driver_tokens SET is_boosted = $1, boost_expires_at = $2 WHERE driver_id = $3`,
            [newBoostState, newBoostState ? new Date(Date.now() + 24*60*60*1000) : null, req.user.id]);
        res.json({ success: true, is_boosted: newBoostState, message: newBoostState ? '⭐ Pauta activada' : 'Pauta desactivada' });
    } catch (error) {
        res.status(500).json({ error: 'Error al cambiar estado' });
    }
});

app.get('/api/admin/stats', authenticateToken, requireRole('ADMIN'), async (req, res) => {
    try {
        const onlineDrivers = await pool.query('SELECT COUNT(*) FROM drivers WHERE is_online = TRUE');
        const activeRides = await pool.query("SELECT COUNT(*) FROM rides WHERE status IN ('REQUESTED', 'ACCEPTED')");
        res.json({
            success: true,
            stats: {
                onlineDrivers: parseInt(onlineDrivers.rows[0].count),
                activeRides: parseInt(activeRides.rows[0].count)
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Error al obtener estadísticas' });
    }
});

app.get('/api/admin/drivers/pending', authenticateToken, requireRole('ADMIN'), async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT u.id, u.name, u.phone, d.vehicle_plate, d.is_approved FROM drivers d JOIN users u ON d.user_id = u.id WHERE d.is_approved = FALSE ORDER BY d.created_at DESC`
        );
        res.json({ success: true, drivers: result.rows });
    } catch (error) {
        res.status(500).json({ error: 'Error al listar conductores' });
    }
});

app.put('/api/admin/drivers/:driverId', authenticateToken, requireRole('ADMIN'), async (req, res) => {
    try {
        const { driverId } = req.params;
        const { status } = req.body;
        if (!['APPROVED', 'REJECTED'].includes(status)) return res.status(400).json({ error: 'Estado inválido' });
        const result = await pool.query(`UPDATE drivers SET is_approved = $1 WHERE user_id = $2 RETURNING user_id, is_approved`,
            [status === 'APPROVED', driverId]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Conductor no encontrado' });
        res.json({ success: true, message: status === 'APPROVED' ? '✅ Conductor aprobado' : '❌ Conductor rechazado' });
    } catch (error) {
        res.status(500).json({ error: 'Error al actualizar conductor' });
    }
});

io.on('connection', (socket) => {
    console.log(`📱 Dispositivo conectado: ${socket.id}`);
    
    socket.on('driver_online', async (data) => {
        try {
            const { driverId, lat, lng } = data;
            await pool.query(`UPDATE drivers SET is_online = TRUE, current_lat = $1, current_lng = $2, last_updated = NOW() WHERE user_id = $3`, [lat, lng, driverId]);
            socket.join('drivers_online');
            socket.driverId = driverId;
            console.log(`🏍️ Conductor ${driverId} en línea`);
        } catch (error) {
            console.error('Error al poner conductor en línea:', error);
        }
    });
    
    socket.on('location_update', async (data) => {
        try {
            const { driverId, lat, lng } = data;
            await pool.query(`UPDATE drivers SET current_lat = $1, current_lng = $2, last_updated = NOW() WHERE user_id = $3`, [lat, lng, driverId]);
            socket.to(`ride_${driverId}`).emit('driver_moved', { driverId, lat, lng });
            socket.to('admin_room').emit('driver_location', { driverId, lat, lng });
        } catch (error) {
            console.error('Error actualizando ubicación:', error);
        }
    });
    
    socket.on('join_ride', (data) => {
        const { driverId } = data;
        socket.join(`ride_${driverId}`);
    });
    
    socket.on('user_auth', (data) => {
        const { userId } = data;
        socket.join(`user_${userId}`);
    });
    
    socket.on('admin_connect', () => {
        socket.join('admin_room');
    });
    
    socket.on('disconnect', async () => {
        if (socket.driverId) {
            try {
                await pool.query('UPDATE drivers SET is_online = FALSE WHERE user_id = $1', [socket.driverId]);
                console.log(`❌ Conductor ${socket.driverId} desconectado`);
            } catch (error) {
                console.error('Error al desconectar:', error);
            }
        }
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log('\n🚀 =========================================');
    console.log('🏍️  MotoApp Backend - Jamundí');
    console.log(`🚀  Servidor corriendo en puerto ${PORT}`);
    console.log(`🌐  URL: http://localhost:${PORT}`);
    console.log('🛰️  WebSockets activos');
    console.log('🗄️  Base de datos: Supabase');
    console.log('🚀 =========================================\n');
});
