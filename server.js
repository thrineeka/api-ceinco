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




app.get('/', (req, res) => {
    console.log(`${colors.green}Solicitud GET / recibida. Sirviendo la página de bienvenida HTML.${colors.reset}`);
    res.sendFile(__dirname + '/index.html'); // Esto servirá el index.html que creaste
});


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

// --- Rutas de API para Usuarios ---

// Endpoint: Registra un nuevo usuario con todos los campos obligatorios.
app.post('/api/usuarios/registro', async (req, res) => {
    const {
        nombre_usuario,
        contrasena,
        rol,
        primer_nombre,
        apellido_paterno,
        apellido_materno,
        email,
        telefono,
        tipo_documento,
        numero_documento,
    } = req.body;

    if (!nombre_usuario || !contrasena || !primer_nombre || !apellido_paterno || !apellido_materno || !email || !telefono || !tipo_documento || !numero_documento) {
        return res.status(400).json({ error: 'Por favor, complete todos los campos obligatorios: nombre de usuario, contraseña, primer nombre, apellido paterno, apellido materno, email, teléfono, tipo de documento, y número de documento.' });
    }

    const userRol = rol || 'Paciente';

    try {
        const [rows] = await pool.execute(
            'SELECT id_usuario FROM usuarios WHERE nombre_usuario = ? OR email = ?',
            [nombre_usuario, email]
        );

        if (rows.length > 0) {
            console.log(`${colors.yellow}[ADVERTENCIA] Intento de registro con usuario o email existente: ${nombre_usuario || email}${colors.reset}`);
            return res.status(400).json({ error: 'El nombre de usuario o el correo electrónico ya están registrados.' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(contrasena, salt);

        const [result] = await pool.execute(
            `INSERT INTO usuarios (nombre_usuario, contrasena, rol, primer_nombre, apellido_paterno, apellido_materno, email, telefono, tipo_documento, numero_documento)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                nombre_usuario,
                hashedPassword,
                userRol,
                primer_nombre,
                apellido_paterno,
                apellido_materno,
                email,
                telefono,
                tipo_documento,
                numero_documento,
            ]
        );

        console.log(`${colors.magenta}[ALERT] Nuevo usuario registrado exitosamente: ${nombre_usuario} (ID: ${result.insertId}, Rol: ${userRol})${colors.reset}`);

        const token = jwt.sign(
            { id: result.insertId, rol: userRol, nombre_usuario: nombre_usuario },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.status(201).json({
            mensaje: 'Usuario registrado exitosamente',
            id_usuario: result.insertId,
            token,
            usuario: {
                id_usuario: result.insertId,
                nombre_usuario,
                rol: userRol,
                primer_nombre,
                email
            }
        });

    } catch (error) {
        console.error(`${colors.red}Error al registrar usuario:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al registrar el usuario.' });
    }
});

// Endpoint: Permite a un usuario iniciar sesión y obtener un token JWT.
app.post('/api/auth/login', async (req, res) => {
    const { nombre_usuario, contrasena } = req.body;

    if (!nombre_usuario || !contrasena) {
        console.log(`${colors.yellow}[ADVERTENCIA] Intento de inicio de sesión sin credenciales completas.${colors.reset}`);
        return res.status(400).json({ error: 'Por favor, ingrese su nombre de usuario y contraseña.' });
    }

    try {
        const [rows] = await pool.execute(
            'SELECT id_usuario, nombre_usuario, contrasena, rol, primer_nombre, email FROM usuarios WHERE nombre_usuario = ?',
            [nombre_usuario]
        );

        if (rows.length === 0) {
            console.log(`${colors.yellow}[ADVERTENCIA] Intento de inicio de sesión fallido para usuario: ${nombre_usuario} (Usuario no encontrado).${colors.reset}`);
            return res.status(401).json({ error: 'Credenciales inválidas.' });
        }

        const user = rows[0];

        const isMatch = await bcrypt.compare(contrasena, user.contrasena);

        if (!isMatch) {
            console.log(`${colors.yellow}[ADVERTENCIA] Intento de inicio de sesión fallido para usuario: ${nombre_usuario} (Contraseña incorrecta).${colors.reset}`);
            return res.status(401).json({ error: 'Credenciales inválidas.' });
        }

        const token = jwt.sign(
            { id: user.id_usuario, rol: user.rol, nombre_usuario: user.nombre_usuario },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        console.log(`${colors.green}[ALERT] Inicio de sesión exitoso para el usuario: ${user.nombre_usuario} (Rol: ${user.rol})${colors.reset}`);

        res.status(200).json({
            mensaje: 'Inicio de sesión exitoso.',
            token,
            usuario: {
                id_usuario: user.id_usuario,
                nombre_usuario: user.nombre_usuario,
                rol: user.rol,
                primer_nombre: user.primer_nombre,
                email: user.email
            }
        });

    } catch (error) {
        console.error(`${colors.red}Error al iniciar sesión:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al iniciar sesión.' });
    }
});

// Endpoint: Obtiene el perfil del usuario autenticado.
app.get('/api/usuarios/perfil', verifyToken, async (req, res) => {
    try {
        const [rows] = await pool.execute(
            `SELECT id_usuario, nombre_usuario, rol, primer_nombre, apellido_paterno, apellido_materno,
             email, telefono, tipo_documento, numero_documento, fecha_creacion, fecha_actualizacion
             FROM usuarios WHERE id_usuario = ?`,
            [req.user.id]
        );

        if (rows.length === 0) {
            console.log(`${colors.yellow}[ADVERTENCIA] Intento de obtener usuario no encontrado: ID ${req.user.id}${colors.reset}`);
            return res.status(404).json({ error: 'Usuario no encontrado.' });
        }

        const userData = rows[0];
        console.log(`${colors.cyan}Perfil obtenido para usuario: ${userData.nombre_usuario} (ID: ${userData.id_usuario})${colors.reset}`);
        res.status(200).json(userData);

    } catch (error) {
        console.error(`${colors.red}Error al obtener perfil de usuario:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al obtener el perfil.' });
    }
});

// Endpoint: Obtiene todos los usuarios (solo para administradores).
app.get('/api/usuarios', verifyToken, async (req, res) => {
    if (req.user.rol !== 'Administrador') {
        console.log(`${colors.red}[ACCESO DENEGADO] Intento de listar usuarios no autorizado por ${req.user.nombre_usuario} (ID: ${req.user.id}, Rol: ${req.user.rol})${colors.reset}`);
        return res.status(403).json({ error: 'Acceso denegado. Solo los administradores pueden listar usuarios.' });
    }

    try {
        const [rows] = await pool.execute(
            `SELECT id_usuario, nombre_usuario, rol, primer_nombre, apellido_paterno, apellido_materno,
             email, telefono, fecha_creacion FROM usuarios`
        );
        console.log(`${colors.cyan}Obtenidos ${rows.length} usuarios.${colors.reset}`);
        res.status(200).json(rows);
    } catch (error) {
        console.error(`${colors.red}Error al obtener usuarios:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al obtener usuarios.' });
    }
});

// Endpoint: Obtiene un usuario por ID (admin o el propio usuario).
app.get('/api/usuarios/:id', verifyToken, async (req, res) => {
    const userId = req.params.id;

    if (req.user.id !== parseInt(userId) && req.user.rol !== 'Administrador') {
        console.log(`${colors.red}[ACCESO DENEGADO] Intento de acceso no autorizado a perfil de usuario ${userId} por ${req.user.nombre_usuario} (ID: ${req.user.id}, Rol: ${req.user.rol})${colors.reset}`);
        return res.status(403).json({ error: 'Acceso denegado. No tiene permisos para ver este perfil.' });
    }

    try {
        const [rows] = await pool.execute(
            `SELECT id_usuario, nombre_usuario, rol, primer_nombre, apellido_paterno, apellido_materno,
             email, telefono, tipo_documento, numero_documento, fecha_creacion, fecha_actualizacion
             FROM usuarios WHERE id_usuario = ?`,
            [userId]
        );

        if (rows.length === 0) {
            console.log(`${colors.yellow}[ADVERTENCIA] Intento de obtener usuario no encontrado: ID ${userId}${colors.reset}`);
            return res.status(404).json({ error: 'Usuario no encontrado.' });
        }

        console.log(`${colors.cyan}Usuario obtenido: ${rows[0].nombre_usuario} (ID: ${rows[0].id_usuario})${colors.reset}`);
        res.status(200).json(rows[0]);

    } catch (error) {
        console.error(`${colors.red}Error al obtener usuario:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al obtener el usuario.' });
    }
});

// Endpoint: Actualiza la información de un usuario (admin o el propio usuario).
app.put('/api/usuarios/:id', verifyToken, async (req, res) => {
    const userId = req.params.id;
    const {
        nombre_usuario,
        contrasena,
        rol,
        primer_nombre,
        apellido_paterno,
        apellido_materno,
        email,
        telefono,
        tipo_documento,
        numero_documento,
    } = req.body;

    if (req.user.id !== parseInt(userId)) {
        if (req.user.rol !== 'Administrador') {
            console.log(`${colors.red}[ACCESO DENEGADO] Intento de edición no autorizado de perfil ${userId} por ${req.user.nombre_usuario} (ID: ${req.user.id}, Rol: ${req.user.rol})${colors.reset}`);
            return res.status(403).json({ error: 'Acceso denegado. Solo puede editar su propio perfil.' });
        }
    }

    try {
        let updateQuery = `UPDATE usuarios SET `;
        const updateParams = [];
        const fieldsToUpdate = [];

        if (nombre_usuario !== undefined && nombre_usuario !== '') {
            fieldsToUpdate.push('nombre_usuario = ?');
            updateParams.push(nombre_usuario);
        }
        if (contrasena !== undefined && contrasena !== '') {
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(contrasena, salt);
            fieldsToUpdate.push('contrasena = ?');
            updateParams.push(hashedPassword);
        }
        if (primer_nombre !== undefined && primer_nombre !== '') {
            fieldsToUpdate.push('primer_nombre = ?');
            updateParams.push(primer_nombre);
        }
        if (apellido_paterno !== undefined && apellido_paterno !== '') {
            fieldsToUpdate.push('apellido_paterno = ?');
            updateParams.push(apellido_paterno);
        }
        if (apellido_materno !== undefined) {
            fieldsToUpdate.push('apellido_materno = ?');
            updateParams.push(apellido_materno === '' ? null : apellido_materno);
        }
        if (email !== undefined && email !== '') {
            fieldsToUpdate.push('email = ?');
            updateParams.push(email);
        }
        if (telefono !== undefined) {
            fieldsToUpdate.push('telefono = ?');
            updateParams.push(telefono === '' ? null : telefono);
        }
        if (tipo_documento !== undefined) {
            fieldsToUpdate.push('tipo_documento = ?');
            updateParams.push(tipo_documento === '' ? null : tipo_documento);
        }
        if (numero_documento !== undefined) {
            fieldsToUpdate.push('numero_documento = ?');
            updateParams.push(numero_documento === '' ? null : numero_documento);
        }

        if (req.user.rol === 'Administrador' && rol !== undefined && rol !== '') {
            fieldsToUpdate.push('rol = ?');
            updateParams.push(rol);
        }

        if (fieldsToUpdate.length === 0) {
            return res.status(400).json({ error: 'No hay datos para actualizar.' });
        }

        fieldsToUpdate.push('fecha_actualizacion = CURRENT_TIMESTAMP()');

        updateQuery += fieldsToUpdate.join(', ') + ' WHERE id_usuario = ?';
        updateParams.push(userId);

        const [result] = await pool.execute(updateQuery, updateParams);

        if (result.affectedRows === 0) {
            console.log(`${colors.yellow}[ADVERTENCIA] Intento de actualizar usuario no encontrado o sin cambios: ID ${userId}${colors.reset}`);
            return res.status(404).json({ error: 'Usuario no encontrado o no se realizaron cambios.' });
        }

        const [updatedUserRows] = await pool.execute(
            `SELECT id_usuario, nombre_usuario, rol, primer_nombre, apellido_paterno, apellido_materno,
             email, telefono, tipo_documento, numero_documento, fecha_creacion, fecha_actualizacion
             FROM usuarios WHERE id_usuario = ?`,
            [userId]
        );
        console.log(`${colors.cyan}Usuario actualizado: ${updatedUserRows[0].nombre_usuario} (ID: ${updatedUserRows[0].id_usuario})${colors.reset}`);
        res.status(200).json({ mensaje: 'Usuario actualizado exitosamente', usuario: updatedUserRows[0] });

    } catch (error) {
        console.error(`${colors.red}Error al actualizar usuario:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al actualizar el usuario.' });
    }
});

// --- Rutas de API para Doctores ---

// Endpoint: Obtiene todos los doctores.
app.get('/api/doctores', async (req, res) => {
    try {
        const [rows] = await pool.execute('SELECT id_doctor, nombre, apellido FROM doctores');
        console.log(`${colors.cyan}Obtenidos ${rows.length} doctores.${colors.reset}`);
        res.status(200).json(rows);
    } catch (error) {
        console.error(`${colors.red}Error al obtener doctores:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al obtener doctores.' });
    }
});

// Endpoint: Obtiene un doctor específico por ID.
app.get('/api/doctores/:id', async (req, res) => {
    const doctorId = req.params.id;
    try {
        const [rows] = await pool.execute('SELECT id_doctor, nombre, apellido FROM doctores WHERE id_doctor = ?', [doctorId]);
        if (rows.length === 0) {
            console.log(`${colors.yellow}[ADVERTENCIA] Intento de obtener doctor no encontrado: ID ${doctorId}${colors.reset}`);
            return res.status(404).json({ error: 'Doctor no encontrado.' });
        }
        console.log(`${colors.cyan}Doctor obtenido: ${rows[0].nombre} ${rows[0].apellido} (ID: ${rows[0].id_doctor})${colors.reset}`);
        res.status(200).json(rows[0]);
    } catch (error) {
        console.error(`${colors.red}Error al obtener doctor:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al obtener el doctor.' });
    }
});

// Endpoint: Agrega un nuevo doctor (solo para administradores).
app.post('/api/doctores', verifyToken, async (req, res) => {
    if (req.user.rol !== 'Administrador') {
        console.log(`${colors.red}[ACCESO DENEGADO] Intento de agregar doctor no autorizado por ${req.user.nombre_usuario} (ID: ${req.user.id}, Rol: ${req.user.rol})${colors.reset}`);
        return res.status(403).json({ error: 'Acceso denegado. Solo los administradores pueden agregar doctores.' });
    }

    const { nombre, apellido } = req.body;

    if (!nombre || !apellido) {
        return res.status(400).json({ error: 'Por favor, proporcione el nombre y apellido del doctor.' });
    }

    try {
        const [result] = await pool.execute(
            'INSERT INTO doctores (nombre, apellido) VALUES (?, ?)',
            [nombre, apellido]
        );
        console.log(`${colors.green}[ALERT] Nuevo doctor agregado: ${nombre} ${apellido} (ID: ${result.insertId})${colors.reset}`);
        res.status(201).json({ mensaje: 'Doctor agregado exitosamente', id_doctor: result.insertId });
    } catch (error) {
        console.error(`${colors.red}Error al agregar doctor:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al agregar el doctor.' });
    }
});

// Endpoint: Actualiza la información de un doctor existente (solo para administradores).
app.put('/api/doctores/:id', verifyToken, async (req, res) => {
    if (req.user.rol !== 'Administrador') {
        console.log(`${colors.red}[ACCESO DENEGADO] Intento de actualizar doctor no autorizado por ${req.user.nombre_usuario} (ID: ${req.user.id}, Rol: ${req.user.rol})${colors.reset}`);
        return res.status(403).json({ error: 'Acceso denegado. Solo los administradores pueden actualizar doctores.' });
    }

    const doctorId = req.params.id;
    const { nombre, apellido } = req.body;

    if (!nombre && !apellido) {
        return res.status(400).json({ error: 'No hay datos para actualizar.' });
    }

    try {
        let updateQuery = `UPDATE doctores SET `;
        const updateParams = [];
        const fieldsToUpdate = [];

        if (nombre !== undefined && nombre !== '') {
            fieldsToUpdate.push('nombre = ?');
            updateParams.push(nombre);
        }
        if (apellido !== undefined && apellido !== '') {
            fieldsToUpdate.push('apellido = ?');
            updateParams.push(apellido);
        }

        updateQuery += fieldsToUpdate.join(', ') + ' WHERE id_doctor = ?';
        updateParams.push(doctorId);

        const [result] = await pool.execute(updateQuery, updateParams);

        if (result.affectedRows === 0) {
            console.log(`${colors.yellow}[ADVERTENCIA] Intento de actualizar doctor no encontrado o sin cambios: ID ${doctorId}${colors.reset}`);
            return res.status(404).json({ error: 'Doctor no encontrado o no se realizaron cambios.' });
        }
        console.log(`${colors.green}[ALERT] Doctor actualizado: ID ${doctorId}${colors.reset}`);
        res.status(200).json({ mensaje: 'Doctor actualizado exitosamente' });
    } catch (error) {
        console.error(`${colors.red}Error al actualizar doctor:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al actualizar el doctor.' });
    }
});

// Endpoint: Elimina un doctor (solo para administradores).
app.delete('/api/doctores/:id', verifyToken, async (req, res) => {
    if (req.user.rol !== 'Administrador') {
        console.log(`${colors.red}[ACCESO DENEGADO] Intento de eliminar doctor no autorizado por ${req.user.nombre_usuario} (ID: ${req.user.id}, Rol: ${req.user.rol})${colors.reset}`);
        return res.status(403).json({ error: 'Acceso denegado. Solo los administradores pueden eliminar doctores.' });
    }

    const doctorId = req.params.id;

    try {
        const [citas] = await pool.execute('SELECT id_cita FROM citas WHERE id_doctor = ?', [doctorId]);

        if (citas.length > 0) {
            console.log(`${colors.yellow}[ADVERTENCIA] Intento de eliminar doctor con citas asociadas: ID ${doctorId}${colors.reset}`);
            return res.status(400).json({
                error: 'No se puede eliminar el doctor porque tiene citas asociadas. Elimine las citas primero.'
            });
        }

        const [result] = await pool.execute('DELETE FROM doctores WHERE id_doctor = ?', [doctorId]);

        if (result.affectedRows === 0) {
            console.log(`${colors.yellow}[ADVERTENCIA] Intento de eliminar doctor no encontrado: ID ${doctorId}${colors.reset}`);
            return res.status(404).json({ error: 'Doctor no encontrado.' });
        }
        console.log(`${colors.green}[ALERT] Doctor eliminado: ID ${doctorId}${colors.reset}`);
        res.status(200).json({ mensaje: 'Doctor eliminado exitosamente.' });
    } catch (error) {
        console.error(`${colors.red}Error al eliminar doctor:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al eliminar el doctor.' });
    }
});

// --- Rutas de API para Horarios de Doctores ---

// Endpoint: Obtiene los horarios de un doctor específico, opcionalmente filtrados por fecha.
app.get('/api/doctores/:id/horarios', async (req, res) => {
    const doctorId = req.params.id;
    const { fecha } = req.query;

    try {
        let query = 'SELECT id_horario, id_doctor, fecha, hora_inicio, hora_fin FROM horarios_doctores WHERE id_doctor = ?';
        const queryParams = [doctorId];

        if (fecha) {
            query += ' AND fecha = ?';
            queryParams.push(fecha);
        }

        const [rows] = await pool.execute(query, queryParams);
        console.log(`${colors.cyan}Obtenidos ${rows.length} horarios para el doctor ID ${doctorId}${fecha ? ` en la fecha ${fecha}` : ''}.${colors.reset}`);
        res.status(200).json(rows);
    } catch (error) {
        console.error(`${colors.red}Error al obtener horarios del doctor:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al obtener horarios del doctor.' });
    }
});

// Endpoint: Agrega un nuevo horario para un doctor (solo para administradores).
app.post('/api/horarios', verifyToken, async (req, res) => {
    if (req.user.rol !== 'Administrador') {
        console.log(`${colors.red}[ACCESO DENEGADO] Intento de agregar horario no autorizado por ${req.user.nombre_usuario} (ID: ${req.user.id}, Rol: ${req.user.rol})${colors.reset}`);
        return res.status(403).json({ error: 'Acceso denegado. Solo los administradores pueden agregar horarios.' });
    }

    const { id_doctor, fecha, hora_inicio, hora_fin } = req.body;

    if (!id_doctor || !fecha || !hora_inicio || !hora_fin) {
        return res.status(400).json({
            error: 'Por favor, proporcione todos los campos requeridos para el horario: id_doctor, fecha, hora_inicio, hora_fin.'
        });
    }

    try {
        const [doctor] = await pool.execute('SELECT id_doctor FROM doctores WHERE id_doctor = ?', [id_doctor]);
        if (doctor.length === 0) {
            console.log(`${colors.yellow}[ADVERTENCIA] Intento de agregar horario para doctor no existente: ID ${id_doctor}${colors.reset}`);
            return res.status(404).json({ error: 'Doctor no encontrado.' });
        }

        const [existingSchedule] = await pool.execute(
            'SELECT id_horario FROM horarios_doctores WHERE id_doctor = ? AND fecha = ? AND ((hora_inicio < ? AND hora_fin > ?) OR (hora_inicio < ? AND hora_fin > ?))',
            [id_doctor, fecha, hora_fin, hora_inicio, hora_inicio, hora_fin]
        );

        if (existingSchedule.length > 0) {
            return res.status(400).json({ error: 'Ya existe un horario que se superpone para este doctor en esta fecha.' });
        }


        const [result] = await pool.execute(
            'INSERT INTO horarios_doctores (id_doctor, fecha, hora_inicio, hora_fin) VALUES (?, ?, ?, ?)',
            [id_doctor, fecha, hora_inicio, hora_fin]
        );
        console.log(`${colors.green}[ALERT] Horario agregado para doctor ID ${id_doctor} (Fecha: ${fecha}, Horario: ${hora_inicio}-${hora_fin})${colors.reset}`);
        res.status(201).json({ mensaje: 'Horario agregado exitosamente', id_horario: result.insertId });
    } catch (error) {
        console.error(`${colors.red}Error al agregar horario:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al agregar el horario.' });
    }
});

// Endpoint: Actualiza un horario de doctor existente (solo para administradores).
app.put('/api/horarios/:id', verifyToken, async (req, res) => {
    if (req.user.rol !== 'Administrador') {
        console.log(`${colors.red}[ACCESO DENEGADO] Intento de actualizar horario no autorizado por ${req.user.nombre_usuario} (ID: ${req.user.id}, Rol: ${req.user.rol})${colors.reset}`);
        return res.status(403).json({ error: 'Acceso denegado. Solo los administradores pueden actualizar horarios.' });
    }

    const horarioId = req.params.id;
    const { fecha, hora_inicio, hora_fin } = req.body;

    if (!fecha && !hora_inicio && !hora_fin) {
        return res.status(400).json({ error: 'No hay datos para actualizar.' });
    }

    try {
        let updateQuery = `UPDATE horarios_doctores SET `;
        const updateParams = [];
        const fieldsToUpdate = [];

        if (fecha !== undefined && fecha !== '') {
            fieldsToUpdate.push('fecha = ?');
            updateParams.push(fecha);
        }
        if (hora_inicio !== undefined && hora_inicio !== '') {
            fieldsToUpdate.push('hora_inicio = ?');
            updateParams.push(hora_inicio);
        }
        if (hora_fin !== undefined && hora_fin !== '') {
            fieldsToUpdate.push('hora_fin = ?');
            updateParams.push(hora_fin);
        }

        if (fieldsToUpdate.length === 0) {
            return res.status(400).json({ error: 'No hay datos para actualizar.' });
        }

        updateQuery += fieldsToUpdate.join(', ') + ' WHERE id_horario = ?';
        updateParams.push(horarioId);

        const [result] = await pool.execute(updateQuery, updateParams);

        if (result.affectedRows === 0) {
            console.log(`${colors.yellow}[ADVERTENCIA] Intento de actualizar horario no encontrado o sin cambios: ID ${horarioId}${colors.reset}`);
            return res.status(404).json({ error: 'Horario no encontrado o no se realizaron cambios.' });
        }
        console.log(`${colors.green}[ALERT] Horario actualizado: ID ${horarioId}${colors.reset}`);
        res.status(200).json({ mensaje: 'Horario actualizado exitosamente' });
    } catch (error) {
        console.error(`${colors.red}Error al actualizar horario:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al actualizar el horario.' });
    }
});

// Endpoint: Elimina un horario de doctor (solo para administradores).
app.delete('/api/horarios/:id', verifyToken, async (req, res) => {
    if (req.user.rol !== 'Administrador') {
        console.log(`${colors.red}[ACCESO DENEGADO] Intento de eliminar horario no autorizado por ${req.user.nombre_usuario} (ID: ${req.user.id}, Rol: ${req.user.rol})${colors.reset}`);
        return res.status(403).json({ error: 'Acceso denegado. Solo los administradores pueden eliminar horarios.' });
    }

    const horarioId = req.params.id;

    try {
        const [result] = await pool.execute('DELETE FROM horarios_doctores WHERE id_horario = ?', [horarioId]);

        if (result.affectedRows === 0) {
            console.log(`${colors.yellow}[ADVERTENCIA] Intento de eliminar horario no encontrado: ID ${horarioId}${colors.reset}`);
            return res.status(404).json({ error: 'Horario no encontrado.' });
        }
        console.log(`${colors.green}[ALERT] Horario eliminado: ID ${horarioId}${colors.reset}`);
        res.status(200).json({ mensaje: 'Horario eliminado exitosamente.' });
    } catch (error) {
        console.error(`${colors.red}Error al eliminar horario:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al eliminar el horario.' });
    }
});

// Endpoint: Obtiene todas las citas, con filtros por rol de usuario.
app.get('/api/citas', verifyToken, async (req, res) => {
    try {
        let query = `
            SELECT c.id_cita, c.id_usuario, c.id_doctor, c.fecha, c.hora, c.servicio,
                   c.tipo_agendamiento, c.estado, u.primer_nombre as nombre_paciente,
                   u.apellido_paterno as apellido_paciente, d.nombre as nombre_doctor,
                   d.apellido as apellido_doctor
            FROM citas c
            LEFT JOIN usuarios u ON c.id_usuario = u.id_usuario
            LEFT JOIN doctores d ON c.id_doctor = d.id_doctor
        `;
        const queryParams = [];

        if (req.user.rol !== 'Administrador') {
            query += ' WHERE c.id_usuario = ?';
            queryParams.push(req.user.id);
            console.log(`${colors.cyan}Obteniendo citas para el usuario ID: ${req.user.id}${colors.reset}`);
        } else {
            console.log(`${colors.cyan}Obteniendo todas las citas (Admin).${colors.reset}`);
        }

        const [rows] = await pool.execute(query, queryParams);
        console.log(`${colors.cyan}Obtenidas ${rows.length} citas.${colors.reset}`);
        res.status(200).json(rows);
    } catch (error) {
        console.error(`${colors.red}Error al obtener citas:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al obtener citas.' });
    }
});

// Endpoint: Obtiene citas de un doctor específico, opcionalmente filtradas por fecha.
app.get('/api/citas/doctor/:idDoctor', verifyToken, async (req, res) => {
    const { idDoctor } = req.params;
    const { fecha } = req.query;

    try {
        let query = `
            SELECT c.*, u.primer_nombre AS nombre_paciente, u.apellido_paterno AS apellido_paciente,
                   d.nombre AS nombre_doctor, d.apellido AS apellido_doctor
            FROM citas c
            JOIN usuarios u ON c.id_usuario = u.id_usuario
            JOIN doctores d ON c.id_doctor = d.id_doctor
            WHERE c.id_doctor = ?
        `;
        const queryParams = [idDoctor];

        if (fecha) {
            query += ' AND c.fecha = ?';
            queryParams.push(fecha);
        }

        const [rows] = await pool.execute(query, queryParams);
        res.json(rows);
    } catch (error) {
        console.error(`${colors.red}Error al obtener citas del doctor:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al obtener las citas del doctor.' });
    }
});

// Endpoint: Calcula y obtiene los horarios disponibles de un doctor en una fecha específica.
app.get('/api/doctores/:idDoctor/horarios-disponibles', verifyToken, async (req, res) => {
    const { idDoctor } = req.params;
    const { fecha } = req.query;

    if (!fecha) {
        return res.status(400).json({ error: 'La fecha es requerida para obtener horarios disponibles.' });
    }

    try {
        const [scheduleRows] = await pool.execute(
            'SELECT id_horario, id_doctor, fecha, hora_inicio, hora_fin FROM horarios_doctores WHERE id_doctor = ? AND fecha = ?',
            [idDoctor, fecha]
        );

        if (scheduleRows.length === 0) {
            return res.json([]);
        }

        const [bookedAppointments] = await pool.execute(
            'SELECT hora FROM citas WHERE id_doctor = ? AND fecha = ? AND estado != "Cancelada" AND estado != "Completada"',
            [idDoctor, fecha]
        );
        const bookedTimes = new Set(bookedAppointments.map(app => app.hora));

        const availableSlots = [];
        const thirtyMinutesInMs = 30 * 60 * 1000;

        scheduleRows.forEach(schedule => {
            const [startHour, startMinute] = schedule.hora_inicio.split(':').map(Number);
            const [endHour, endMinute] = schedule.hora_fin.split(':').map(Number);

            let currentTime = new Date(0, 0, 0, startHour, startMinute, 0);
            const endTime = new Date(0, 0, 0, endHour, endMinute, 0);

            while (currentTime.getTime() + thirtyMinutesInMs <= endTime.getTime()) {
                const slotStartTime = currentTime.toTimeString().slice(0, 8);
                const slotEndTime = addMinutesToTime(slotStartTime, 30);

                let isBooked = false;
                for (const bookedTime of bookedTimes) {
                    const bookedStart = bookedTime;
                    const bookedEnd = addMinutesToTime(bookedTime, 30);

                    if ((slotStartTime < bookedEnd && slotEndTime > bookedStart)) {
                        isBooked = true;
                        break;
                    }
                }

                const today = new Date().toISOString().split('T')[0];
                const now = new Date();
                let isPastTime = false;
                if (fecha === today) {
                    const [slotHour, slotMinute] = slotStartTime.split(':').map(Number);
                    const slotDateTime = new Date(now.getFullYear(), now.getMonth(), now.getDate(), slotHour, slotMinute, 0, 0);
                    if (slotDateTime.getTime() <= now.getTime()) {
                        isPastTime = true;
                    }
                }

                if (!isBooked && !isPastTime) {
                    availableSlots.push({
                        ...schedule,
                        hora_inicio: slotStartTime,
                        hora_fin: slotEndTime,
                    });
                }
                currentTime.setMinutes(currentTime.getMinutes() + 30);
            }
        });

        res.json(availableSlots);

    } catch (error) {
        console.error(`${colors.red}Error al obtener horarios disponibles del doctor:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al obtener horarios disponibles.' });
    }
});

function addMinutesToTime(time, minutes) {
    const [hours, mins, secs] = time.split(':').map(Number);
    const date = new Date();
    date.setHours(hours, mins + minutes, secs);
    return date.toTimeString().slice(0, 8);
}

// Endpoint: Crea una nueva cita, con validación de rol y disponibilidad.
app.post('/api/citas', verifyToken, async (req, res) => {
    const { id_usuario, id_doctor, fecha, hora, servicio, tipo_agendamiento, estado } = req.body;

    if (!id_doctor || !fecha || !hora || !servicio) {
        return res.status(400).json({ error: 'Por favor, complete todos los campos obligatorios: id_doctor, fecha, hora, y servicio.' });
    }

    let actualUserId = id_usuario;
    if (req.user.rol === 'Paciente') {
        actualUserId = req.user.id;
    } else if (req.user.rol === 'Administrador') {
        if (!actualUserId) {
            return res.status(400).json({ error: 'Como administrador, debe proporcionar el id_usuario para agendar la cita.' });
        }
    } else {
        return res.status(403).json({ error: 'Acceso denegado. Su rol no tiene permisos para crear citas.' });
    }

    try {
        const [patientRows] = await pool.execute('SELECT id_usuario FROM usuarios WHERE id_usuario = ?', [actualUserId]);
        if (patientRows.length === 0) {
            return res.status(404).json({ error: 'Paciente no encontrado.' });
        }

        const [doctorRows] = await pool.execute('SELECT id_doctor FROM doctores WHERE id_doctor = ?', [id_doctor]);
        if (doctorRows.length === 0) {
            return res.status(404).json({ error: 'Doctor no encontrado.' });
        }

        const [scheduleRows] = await pool.execute(
            'SELECT hora_inicio, hora_fin FROM horarios_doctores WHERE id_doctor = ? AND fecha = ?',
            [id_doctor, fecha]
        );

        if (scheduleRows.length === 0) {
            return res.status(400).json({ error: `El doctor no tiene horario configurado para la fecha ${fecha}.` });
        }

        const schedule = scheduleRows[0];
        const appointmentDateTime = new Date(`${fecha}T${hora}`);
        const scheduleStartDateTime = new Date(`${fecha}T${schedule.hora_inicio}`);
        const scheduleEndDateTime = new Date(`${fecha}T${schedule.hora_fin}`);

        if (appointmentDateTime < scheduleStartDateTime || appointmentDateTime >= scheduleEndDateTime) {
            return res.status(400).json({
                error: `La cita debe estar entre ${schedule.hora_inicio} y ${schedule.hora_fin} para la fecha ${fecha}.`
            });
        }

        const [existingAppointments] = await pool.execute(
            `SELECT id_cita FROM citas
             WHERE id_doctor = ? AND fecha = ? AND hora = ?
             AND estado IN ('Pendiente', 'Confirmada')`,
            [id_doctor, fecha, hora]
        );

        if (existingAppointments.length > 0) {
            return res.status(409).json({ error: 'El doctor ya tiene una cita agendada para esa fecha y hora.' });
        }

        const [result] = await pool.execute(
            `INSERT INTO citas
             (id_usuario, id_doctor, fecha, hora, servicio, tipo_agendamiento, estado)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
                actualUserId,
                id_doctor,
                fecha,
                hora,
                servicio,
                tipo_agendamiento || 'Con Horario',
                estado || 'Pendiente'
            ]
        );

        const [newAppointment] = await pool.execute(
            `SELECT c.id_cita, c.fecha, c.hora, c.servicio, c.estado,
                    u.primer_nombre as nombre_paciente, u.apellido_paterno as apellido_paciente,
                    d.nombre as nombre_doctor, d.apellido as apellido_doctor
             FROM citas c
             JOIN usuarios u ON c.id_usuario = u.id_usuario
             JOIN doctores d ON c.id_doctor = d.id_doctor
             WHERE c.id_cita = ?`,
            [result.insertId]
        );

        console.log(`${colors.green}[ALERT] Nueva cita creada: ID ${result.insertId}${colors.reset}`);
        res.status(201).json({
            mensaje: 'Cita creada exitosamente',
            cita: newAppointment[0]
        });

    } catch (error) {
        console.error(`${colors.red}Error al crear cita:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al crear la cita.' });
    }
});

// Endpoint: Obtiene todas las citas de un paciente específico.
app.get('/api/citas/paciente/:id_paciente', verifyToken, async (req, res) => {
    const id_paciente = req.params.id_paciente;

    // Verificar que el usuario que hace la petición sea el mismo paciente o un administrador.
    if (req.user.id !== parseInt(id_paciente) && req.user.rol !== 'Administrador') {
        console.log(`${colors.red}[ACCESO DENEGADO] Intento de obtener citas de paciente ${id_paciente} no autorizado por ${req.user.nombre_usuario} (ID: ${req.user.id}, Rol: ${req.user.rol})${colors.reset}`);
        return res.status(403).json({ error: 'Acceso denegado. No tiene permisos para ver estas citas.' });
    }

    try {
        const [rows] = await pool.execute(
            `SELECT c.id_cita, c.id_usuario, c.id_doctor, c.fecha, c.hora, c.estado, c.servicio, c.tipo_agendamiento,
                    d.nombre AS doctor_nombre, d.apellido AS doctor_apellido,
                    u.primer_nombre AS paciente_primer_nombre, u.apellido_paterno AS paciente_apellido_paterno
             FROM citas c
             JOIN usuarios u ON c.id_usuario = u.id_usuario
             JOIN doctores d ON c.id_doctor = d.id_doctor
             WHERE c.id_usuario = ?
             ORDER BY c.fecha DESC, c.hora DESC`,
            [id_paciente]
        );

        if (rows.length === 0) {
            console.log(`${colors.yellow}[ADVERTENCIA] No se encontraron citas para el paciente ID: ${id_paciente}${colors.reset}`);
            return res.status(200).json([]); // Devolver un array vacío si no hay citas, no un 404
        }

        console.log(`${colors.green}[ALERT] Citas obtenidas para paciente ID: ${id_paciente}${colors.reset}`);
        res.status(200).json(rows);
    } catch (error) {
        console.error(`${colors.red}Error al obtener citas del paciente:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al obtener las citas del paciente.' });
    }
});

// Endpoint: Actualiza una cita existente, con validación de rol y propiedad.
app.put('/api/citas/:id', verifyToken, async (req, res) => {
    const citaId = req.params.id;
    const { fecha, hora, servicio, tipo_agendamiento, estado, id_doctor, id_usuario } = req.body;

    try {
        const [existingCitaRows] = await pool.execute('SELECT id_usuario FROM citas WHERE id_cita = ?', [citaId]);

        if (existingCitaRows.length === 0) {
            console.log(`${colors.yellow}[ADVERTENCIA] Intento de actualizar cita no encontrada: ID ${citaId}${colors.reset}`);
            return res.status(404).json({ error: 'Cita no encontrada.' });
        }

        const existingCita = existingCitaRows[0];

        if (req.user.rol !== 'Administrador' && existingCita.id_usuario !== req.user.id) {
            console.log(`${colors.red}[ACCESO DENEGADO] Intento de actualizar cita ${citaId} no autorizado por ${req.user.nombre_usuario} (ID: ${req.user.id}, Rol: ${req.user.rol})${colors.reset}`);
            return res.status(403).json({ error: 'Acceso denegado. No tiene permisos para actualizar esta cita.' });
        }

        let updateQuery = `UPDATE citas SET `;
        const updateParams = [];
        const fieldsToUpdate = [];

        if (id_usuario !== undefined && req.user.rol === 'Administrador') {
            fieldsToUpdate.push('id_usuario = ?');
            updateParams.push(id_usuario);
        }
        if (id_doctor !== undefined) {
            fieldsToUpdate.push('id_doctor = ?');
            updateParams.push(id_doctor);
        }
        if (fecha !== undefined && fecha !== '') {
            fieldsToUpdate.push('fecha = ?');
            updateParams.push(fecha);
        }
        if (hora !== undefined && hora !== '') {
            fieldsToUpdate.push('hora = ?');
            updateParams.push(hora);
        }
        if (servicio !== undefined && servicio !== '') {
            fieldsToUpdate.push('servicio = ?');
            updateParams.push(servicio);
        }
        if (tipo_agendamiento !== undefined && tipo_agendamiento !== '') {
            fieldsToUpdate.push('tipo_agendamiento = ?');
            updateParams.push(tipo_agendamiento);
        }
        if (estado !== undefined && estado !== '') {
            fieldsToUpdate.push('estado = ?');
            updateParams.push(estado);
        }

        if (fieldsToUpdate.length === 0) {
            return res.status(400).json({ error: 'No hay datos para actualizar.' });
        }

        updateQuery += fieldsToUpdate.join(', ') + ' WHERE id_cita = ?';
        updateParams.push(citaId);

        const [result] = await pool.execute(updateQuery, updateParams);

        if (result.affectedRows === 0) {
            console.log(`${colors.yellow}[ADVERTENCIA] Intento de actualizar cita sin cambios: ID ${citaId}${colors.reset}`);
            return res.status(200).json({ mensaje: 'No se realizaron cambios en la cita.' });
        }

        const [updatedCitaRows] = await pool.execute(
            `SELECT c.id_cita, c.id_usuario, c.id_doctor, c.fecha, c.hora, c.servicio,
                    c.tipo_agendamiento, c.estado, u.primer_nombre as nombre_paciente,
                    u.apellido_paterno as apellido_paciente, d.nombre as nombre_doctor,
                    d.apellido as apellido_doctor
            FROM citas c
            LEFT JOIN usuarios u ON c.id_usuario = u.id_usuario
            LEFT JOIN doctores d ON c.id_doctor = d.id_doctor
            WHERE c.id_cita = ?`,
            [citaId]
        );

        console.log(`${colors.green}[ALERT] Cita actualizada: ID ${citaId}${colors.reset}`);
        res.status(200).json({ mensaje: 'Cita actualizada exitosamente', cita: updatedCitaRows[0] });

    } catch (error) {
        console.error(`${colors.red}Error al actualizar cita:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al actualizar la cita.' });
    }
});


// Endpoint: Elimina una cita existente, con validación de rol y propiedad.
app.delete('/api/citas/:id', verifyToken, async (req, res) => {
    const citaId = req.params.id;

    try {
        const [existingCitaRows] = await pool.execute('SELECT id_usuario FROM citas WHERE id_cita = ?', [citaId]);

        if (existingCitaRows.length === 0) {
            console.log(`${colors.yellow}[ADVERTENCIA] Intento de eliminar cita no encontrada: ID ${citaId}${colors.reset}`);
            return res.status(404).json({ error: 'Cita no encontrada.' });
        }

        const existingCita = existingCitaRows[0];

        if (req.user.rol !== 'Administrador' && existingCita.id_usuario !== req.user.id) {
            console.log(`${colors.red}[ACCESO DENEGADO] Intento de eliminar cita ${citaId} no autorizado por ${req.user.nombre_usuario} (ID: ${req.user.id}, Rol: ${req.user.rol})${colors.reset}`);
            return res.status(403).json({ error: 'Acceso denegado. No tiene permisos para eliminar esta cita.' });
        }

        const [result] = await pool.execute('DELETE FROM citas WHERE id_cita = ?', [citaId]);

        if (result.affectedRows === 0) {
            console.log(`${colors.yellow}[ADVERTENCIA] Cita no eliminada, posiblemente no encontrada a pesar de la verificación inicial: ID ${citaId}${colors.reset}`);
            return res.status(404).json({ error: 'Cita no encontrada o ya eliminada.' });
        }
        console.log(`${colors.green}[ALERT] Cita eliminada: ID ${citaId}${colors.reset}`);
        res.status(200).json({ mensaje: 'Cita eliminada exitosamente.' });
    } catch (error) {
        console.error(`${colors.red}Error al eliminar cita:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al eliminar la cita.' });
    }
});

// Inicia el servidor
app.listen(PORT, () => {
    console.log(`${colors.cyan}Servidor ejecutándose en el puerto ${PORT}${colors.reset}`);
});
