require('dotenv').config();

const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 5000;


const colors = {
    reset: "\x1b[0m",
    bright: "\x1b[1m",
    dim: "\x1b[2m",
    underscore: "\x1b[4m",
    blink: "\x1b[5m",
    reverse: "\x1b[7m",
    hidden: "\x1b[8m",
    black: "\x1b[30m",
    red: "\x1b[31m",
    green: "\x1b[32m",
    yellow: "\x1b[33m",
    blue: "\x1b[34m",
    magenta: "\x1b[35m",
    cyan: "\x1b[36m",
    white: "\x1b[37m",
    bgBlack: "\x1b[40m",
    bgRed: "\x1b[41m",
    bgGreen: "\x1b[42m",
    bgYellow: "\x1b[43m",
    bgBlue: "\x1b[44m",
    bgMagenta: "\x1b[45m",
    bgCyan: "\x1b[46m",
    bgWhite: "\x1b[47m"
};

app.use(cors());
app.use(express.json());

const dbConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT,
};

let pool;

async function connectToDatabase() {
    try {
        pool = mysql.createPool(dbConfig);
        console.log(`${colors.green}Conexión a MariaDB establecida exitosamente.${colors.reset}`);
    } catch (error) {
        console.error(`${colors.red}Error al conectar a la base de datos:`, error.message, `${colors.reset}`);
        process.exit(1);
    }
}

connectToDatabase();

const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        console.log(`${colors.yellow}[AUTENTICACIÓN FALLIDA] Acceso denegado. No se proporcionó token.${colors.reset}`);
        return res.status(401).json({ error: 'Acceso denegado. No se proporcionó token.' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.log(`${colors.yellow}[AUTENTICACIÓN FALLIDA] Token inválido o expirado: ${err.message}${colors.reset}`);
            return res.status(403).json({ error: 'Token inválido o expirado.' });
        }
        req.user = user;
        next();
    });
};


app.get('/', (req, res) => {
    res.json({ message: 'API del Centro Integral de Corazón funcionando.' });
});

app.post('/api/auth/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Faltan campos obligatorios: email y password.' });
    }
    
    try {
        const salt = await bcrypt.genSalt(10);
        const contrasena_hash = await bcrypt.hash(password, salt);

        const [result] = await pool.execute(
            'INSERT INTO usuarios (email, contrasena_hash) VALUES (?, ?)',
            [email, contrasena_hash]
        );

        console.log(`${colors.cyan}Nuevo usuario registrado con ID: ${result.insertId}${colors.reset}`);
        res.status(201).json({ message: 'Usuario registrado exitosamente.' });
    } catch (error) {
        console.error(`${colors.red}Error al registrar usuario:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Faltan campos obligatorios: email y password.' });
    }

    try {
        const [rows] = await pool.execute(
            'SELECT id_usuario, contrasena_hash FROM usuarios WHERE email = ?',
            [email]
        );

        const user = rows[0];
        if (!user) {
            return res.status(400).json({ error: 'Credenciales inválidas.' });
        }

        const isMatch = await bcrypt.compare(password, user.contrasena_hash);
        if (!isMatch) {
            return res.status(400).json({ error: 'Credenciales inválidas.' });
        }

        const token = jwt.sign(
            { id: user.id_usuario },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        console.log(`${colors.green}Usuario ${email} ha iniciado sesión. Token generado.${colors.reset}`);
        res.status(200).json({ token });
    } catch (error) {
        console.error(`${colors.red}Error al iniciar sesión:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});

app.get('/api/servicios', async (req, res) => {
    try {
        const [rows] = await pool.execute('SELECT * FROM servicios');
        res.status(200).json(rows);
    } catch (error) {
        console.error(`${colors.red}Error al obtener servicios:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});


app.post('/api/citas', async (req, res) => {
    const { nombre, email, telefono, id_servicio, comentarios } = req.body;
    if (!nombre || !email || !telefono || !id_servicio) {
        return res.status(400).json({ error: 'Faltan campos obligatorios para agendar la cita.' });
    }

    try {
        const [result] = await pool.execute(
            'INSERT INTO citas (nombre, email, telefono, id_servicio, comentarios) VALUES (?, ?, ?, ?, ?)',
            [nombre, email, telefono, id_servicio, comentarios]
        );
        console.log(`${colors.cyan}Nueva cita agendada con ID: ${result.insertId}${colors.reset}`);
        res.status(201).json({ message: 'Cita agendada exitosamente.', id_cita: result.insertId });
    } catch (error) {
        console.error(`${colors.red}Error al agendar cita:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});


app.get('/api/citas', verifyToken, async (req, res) => {
    try {
        const [rows] = await pool.execute('SELECT * FROM citas');
        res.status(200).json(rows);
    } catch (error) {
        console.error(`${colors.red}Error al obtener citas:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});


app.post('/api/blog', verifyToken, async (req, res) => {
    const { titulo, slug, contenido, estado, imagen_publicada } = req.body;
    if (!titulo || !slug || !contenido) {
        return res.status(400).json({ error: 'Faltan campos obligatorios para el blog.' });
    }

    try {
        const [result] = await pool.execute(
            'INSERT INTO blog (titulo, slug, contenido, estado, imagen_publicada) VALUES (?, ?, ?, ?, ?)',
            [titulo, slug, contenido, estado, imagen_publicada]
        );
        console.log(`${colors.cyan}Nueva publicación de blog creada con ID: ${result.insertId}${colors.reset}`);
        res.status(201).json({ message: 'Publicación de blog creada exitosamente.', id_blog: result.insertId });
    } catch (error) {
        console.error(`${colors.red}Error al crear blog:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});


app.get('/api/blog', async (req, res) => {
    try {
        const [rows] = await pool.execute('SELECT * FROM blog WHERE estado = "publicado"');
        res.status(200).json(rows);
    } catch (error) {
        console.error(`${colors.red}Error al obtener publicaciones de blog:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});


app.get('/api/blog/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.execute('SELECT * FROM blog WHERE id_blog = ? AND estado = "publicado"', [id]);
        if (rows.length === 0) {
            return res.status(404).json({ error: 'Publicación de blog no encontrada.' });
        }
        res.status(200).json(rows[0]);
    } catch (error) {
        console.error(`${colors.red}Error al obtener publicación de blog:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});


app.post('/api/consultas', verifyToken, async (req, res) => {
    const { id_cita, fecha, apellidos, nombres, edad, grupo, telefono, hc, id_servicio, dni, observacion, estado } = req.body;
    if (!fecha || !apellidos || !nombres || !id_servicio) {
        return res.status(400).json({ error: 'Faltan campos obligatorios para la consulta.' });
    }

    try {
        const [result] = await pool.execute(
            'INSERT INTO consultas_pacientes (id_cita, fecha, apellidos, nombres, edad, grupo, telefono, hc, id_servicio, dni, observacion, estado) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [id_cita, fecha, apellidos, nombres, edad, grupo, telefono, hc, id_servicio, dni, observacion, estado]
        );
        console.log(`${colors.cyan}Nueva consulta creada con ID: ${result.insertId}${colors.reset}`);
        res.status(201).json({ message: 'Consulta creada exitosamente.', id_consulta: result.insertId });
    } catch (error) {
        console.error(`${colors.red}Error al crear consulta:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});

app.get('/api/consultas', verifyToken, async (req, res) => {
    try {
        const [rows] = await pool.execute('SELECT * FROM consultas_pacientes');
        res.status(200).json(rows);
    } catch (error) {
        console.error(`${colors.red}Error al obtener consultas:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});

app.get('/api/consultas/:id', verifyToken, async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.execute('SELECT * FROM consultas_pacientes WHERE id_consulta = ?', [id]);
        if (rows.length === 0) {
            return res.status(404).json({ error: 'Consulta no encontrada.' });
        }
        res.status(200).json(rows[0]);
    } catch (error) {
        console.error(`${colors.red}Error al obtener consulta:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});

app.listen(PORT, () => {
    console.log(`${colors.bgBlue}${colors.white}Servidor corriendo en el puerto ${PORT}${colors.reset}`);
});
