require('dotenv').config();

const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 2004;

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
    database: process.env.DB_DATABASE,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};

let pool;

async function connectToDatabase() {
    try {
        pool = mysql.createPool(dbConfig);
        await pool.getConnection(); // Try to get a connection to test
        console.log(`${colors.green}Conectado a la base de datos MariaDB!${colors.reset}`);
    } catch (error) {
        console.error(`${colors.red}Error al conectar a la base de datos:`, error.message, `${colors.reset}`);
        process.exit(1); // Exit process if cannot connect to DB
    }
}

connectToDatabase();

// Middleware para verificar el token JWT
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        console.log(`${colors.yellow}[AUTENTICACION FALLIDA] No se proporcionó token. ${colors.reset}`);
        return res.status(401).json({ error: 'Acceso denegado. No se proporcionó token.' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.log(`${colors.red}[AUTENTICACION FALLIDA] Token inválido o expirado. ${err.message}${colors.reset}`);
            return res.status(403).json({ error: 'Token inválido o expirado.' });
        }
        req.user = user;
        console.log(`${colors.cyan}[AUTENTICACION EXITOSA] Usuario: ${user.nombre_usuario} (ID: ${user.id}, Rol: ${user.rol})${colors.reset}`);
        next();
    });
};

// Rutas de Usuarios
// Registrar un nuevo usuario
app.post('/api/usuarios/registro', async (req, res) => {
    const {
        nombre_usuario,
        contrasena,
        primer_nombre,
        apellido_paterno,
        apellido_materno,
        email,
        telefono,
        direccion,
        fecha_nacimiento,
        genero,
        rol
    } = req.body;

    if (!nombre_usuario || !contrasena || !primer_nombre || !apellido_paterno || !email || !telefono) {
        console.log(`${colors.yellow}[VALIDACION FALLIDA] Campos de registro de usuario incompletos. ${colors.reset}`);
        return res.status(400).json({ error: 'Todos los campos obligatorios deben ser completados.' });
    }

    const userRol = rol || 'Paciente'; // Rol por defecto si no se especifica

    try {
        // Verificar si el nombre de usuario o el email ya existen
        const [rows] = await pool.execute('SELECT id_usuario FROM usuarios WHERE nombre_usuario = ? OR email = ?', [nombre_usuario, email]);
        if (rows.length > 0) {
            console.log(`${colors.yellow}[REGISTRO FALLIDO] Nombre de usuario o email ya existen. ${colors.reset}`);
            return res.status(409).json({ error: 'El nombre de usuario o el email ya están registrados.' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(contrasena, salt);

        const [result] = await pool.execute(
            `INSERT INTO usuarios (nombre_usuario, contrasena, primer_nombre, apellido_paterno, apellido_materno, email, telefono, direccion, fecha_nacimiento, genero, rol, fecha_creacion, fecha_actualizacion)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
            [nombre_usuario, hashedPassword, primer_nombre, apellido_paterno, apellido_materno, email, telefono, direccion, fecha_nacimiento, genero, userRol]
        );

        const token = jwt.sign({ id: result.insertId, rol: userRol, nombre_usuario: nombre_usuario }, process.env.JWT_SECRET, { expiresIn: '1h' });

        console.log(`${colors.green}[ALERT] Nuevo usuario registrado: ${nombre_usuario} (ID: ${result.insertId}, Rol: ${userRol})${colors.reset}`);
        res.status(201).json({
            mensaje: 'Usuario registrado exitosamente',
            id_usuario: result.insertId,
            nombre_usuario: nombre_usuario,
            rol: userRol,
            token,
            primer_nombre,
            apellido_paterno,
            email
        });
    } catch (error) {
        console.error(`${colors.red}Error al registrar usuario:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al registrar usuario.' });
    }
});

// Iniciar sesión de usuario
app.post('/api/auth/login', async (req, res) => {
    const { nombre_usuario, contrasena } = req.body;

    if (!nombre_usuario || !contrasena) {
        console.log(`${colors.yellow}[VALIDACION FALLIDA] Nombre de usuario o contraseña faltantes en el login. ${colors.reset}`);
        return res.status(400).json({ error: 'Nombre de usuario y contraseña son requeridos.' });
    }

    try {
        const [rows] = await pool.execute('SELECT id_usuario, nombre_usuario, contrasena, rol, primer_nombre, apellido_paterno, email, telefono, direccion, fecha_nacimiento, genero FROM usuarios WHERE nombre_usuario = ?', [nombre_usuario]);
        if (rows.length === 0) {
            console.log(`${colors.yellow}[LOGIN FALLIDO] Usuario no encontrado: ${nombre_usuario}${colors.reset}`);
            return res.status(401).json({ error: 'Credenciales inválidas.' });
        }

        const user = rows[0];
        const isMatch = await bcrypt.compare(contrasena, user.contrasena);

        if (!isMatch) {
            console.log(`${colors.yellow}[LOGIN FALLIDO] Contraseña incorrecta para el usuario: ${nombre_usuario}${colors.reset}`);
            return res.status(401).json({ error: 'Credenciales inválidas.' });
        }

        const token = jwt.sign({ id: user.id_usuario, rol: user.rol, nombre_usuario: user.nombre_usuario }, process.env.JWT_SECRET, { expiresIn: '1h' });

        console.log(`${colors.green}[ALERT] Inicio de sesión exitoso para el usuario: ${nombre_usuario} (ID: ${user.id_usuario}, Rol: ${user.rol})${colors.reset}`);
        res.status(200).json({
            mensaje: 'Inicio de sesión exitoso',
            token,
            usuario: {
                id_usuario: user.id_usuario,
                nombre_usuario: user.nombre_usuario,
                primer_nombre: user.primer_nombre,
                apellido_paterno: user.apellido_paterno,
                email: user.email,
                telefono: user.telefono,
                direccion: user.direccion,
                fecha_nacimiento: user.fecha_nacimiento,
                genero: user.genero,
                rol: user.rol
            }
        });
    } catch (error) {
        console.error(`${colors.red}Error al iniciar sesión:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al iniciar sesión.' });
    }
});

// Obtener el perfil del usuario autenticado
app.get('/api/usuarios/perfil', verifyToken, async (req, res) => {
    try {
        const [rows] = await pool.execute(
            `SELECT id_usuario, nombre_usuario, primer_nombre, apellido_paterno, apellido_materno, email, telefono, direccion, fecha_nacimiento, genero, rol, fecha_creacion, fecha_actualizacion
             FROM usuarios
             WHERE id_usuario = ?`,
            [req.user.id]
        );
        if (rows.length === 0) {
            console.log(`${colors.yellow}[ADVERTENCIA] Perfil de usuario no encontrado para ID: ${req.user.id}${colors.reset}`);
            return res.status(404).json({ error: 'Usuario no encontrado.' });
        }

        const userData = rows[0];
        console.log(`${colors.blue}[INFO] Perfil obtenido para usuario: ${req.user.nombre_usuario} (ID: ${req.user.id})${colors.reset}`);
        res.status(200).json(userData);
    } catch (error) {
        console.error(`${colors.red}Error al obtener perfil de usuario:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al obtener perfil.' });
    }
});

// Obtener todos los usuarios (solo para administradores)
app.get('/api/usuarios', verifyToken, async (req, res) => {
    if (req.user.rol !== 'Administrador') {
        console.log(`${colors.red}[ACCESO DENEGADO] Intento de acceder a todos los usuarios por ${req.user.nombre_usuario} (Rol: ${req.user.rol})${colors.reset}`);
        return res.status(403).json({ error: 'Acceso denegado. Solo los administradores pueden ver todos los usuarios.' });
    }

    try {
        const [rows] = await pool.execute(
            `SELECT id_usuario, nombre_usuario, primer_nombre, apellido_paterno, apellido_materno, email, telefono, direccion, fecha_nacimiento, genero, rol, fecha_creacion, fecha_actualizacion
             FROM usuarios`
        );
        console.log(`${colors.blue}[INFO] Listado de todos los usuarios solicitado por ${req.user.nombre_usuario}${colors.reset}`);
        res.status(200).json(rows);
    } catch (error) {
        console.error(`${colors.red}Error al obtener todos los usuarios:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al obtener usuarios.' });
    }
});

// Obtener un usuario por ID (propio o si es administrador)
app.get('/api/usuarios/:id', verifyToken, async (req, res) => {
    const userId = req.params.id;

    // Permitir acceso solo si es su propio perfil o si es administrador
    if (req.user.id !== parseInt(userId) && req.user.rol !== 'Administrador') {
        console.log(`${colors.red}[ACCESO DENEGADO] Intento de acceder al perfil de otro usuario (${userId}) por ${req.user.nombre_usuario} (ID: ${req.user.id}, Rol: ${req.user.rol})${colors.reset}`);
        return res.status(403).json({ error: 'Acceso denegado. No tiene permisos para ver este usuario.' });
    }

    try {
        const [rows] = await pool.execute(
            `SELECT id_usuario, nombre_usuario, primer_nombre, apellido_paterno, apellido_materno, email, telefono, direccion, fecha_nacimiento, genero, rol, fecha_creacion, fecha_actualizacion
             FROM usuarios
             WHERE id_usuario = ?`,
            [userId]
        );
        if (rows.length === 0) {
            console.log(`${colors.yellow}[ADVERTENCIA] Usuario no encontrado para ID: ${userId}${colors.reset}`);
            return res.status(404).json({ error: 'Usuario no encontrado.' });
        }

        console.log(`${colors.blue}[INFO] Perfil del usuario ${userId} solicitado por ${req.user.nombre_usuario}${colors.reset}`);
        res.status(200).json(rows[0]);
    } catch (error) {
        console.error(`${colors.red}Error al obtener usuario por ID:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al obtener usuario.' });
    }
});

// Actualizar información de un usuario
app.put('/api/usuarios/:id', verifyToken, async (req, res) => {
    const userId = req.params.id;
    const {
        nombre_usuario,
        contrasena,
        primer_nombre,
        apellido_paterno,
        apellido_materno,
        email,
        telefono,
        direccion,
        fecha_nacimiento,
        genero,
        rol
    } = req.body;

    // Un usuario solo puede actualizar su propio perfil, a menos que sea administrador
    if (req.user.id !== parseInt(userId)) {
        if (req.user.rol !== 'Administrador') {
            console.log(`${colors.red}[ACCESO DENEGADO] Intento de actualizar perfil de otro usuario (${userId}) por ${req.user.nombre_usuario} (ID: ${req.user.id}, Rol: ${req.user.rol})${colors.reset}`);
            return res.status(403).json({ error: 'Acceso denegado. No tiene permisos para actualizar este usuario.' });
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
        if (apellido_materno !== undefined && apellido_materno !== '') {
            fieldsToUpdate.push('apellido_materno = ?');
            updateParams.push(apellido_materno);
        }
        if (email !== undefined && email !== '') {
            fieldsToUpdate.push('email = ?');
            updateParams.push(email);
        }
        if (telefono !== undefined && telefono !== '') {
            fieldsToUpdate.push('telefono = ?');
            updateParams.push(telefono);
        }
        if (direccion !== undefined && direccion !== '') {
            fieldsToUpdate.push('direccion = ?');
            updateParams.push(direccion);
        }
        if (fecha_nacimiento !== undefined && fecha_nacimiento !== '') {
            fieldsToUpdate.push('fecha_nacimiento = ?');
            updateParams.push(fecha_nacimiento);
        }
        if (genero !== undefined && genero !== '') {
            fieldsToUpdate.push('genero = ?');
            updateParams.push(genero);
        }
        // Solo un administrador puede cambiar el rol
        if (req.user.rol === 'Administrador' && rol !== undefined && rol !== '') {
            fieldsToUpdate.push('rol = ?');
            updateParams.push(rol);
        }

        if (fieldsToUpdate.length === 0) {
            console.log(`${colors.yellow}[ADVERTENCIA] No hay datos para actualizar para el usuario ID: ${userId}${colors.reset}`);
            return res.status(400).json({ error: 'No hay datos para actualizar.' });
        }

        fieldsToUpdate.push('fecha_actualizacion = NOW()');

        updateQuery += fieldsToUpdate.join(', ') + ' WHERE id_usuario = ?';
        updateParams.push(userId);

        const [result] = await pool.execute(updateQuery, updateParams);

        if (result.affectedRows === 0) {
            console.log(`${colors.yellow}[ADVERTENCIA] Usuario no actualizado, posiblemente no encontrado: ID ${userId}${colors.reset}`);
            return res.status(404).json({ error: 'Usuario no encontrado o no se realizaron cambios.' });
        }

        // Obtener los datos actualizados del usuario para devolverlos en la respuesta
        const [updatedUserRows] = await pool.execute(
            `SELECT id_usuario, nombre_usuario, primer_nombre, apellido_paterno, apellido_materno, email, telefono, direccion, fecha_nacimiento, genero, rol, fecha_creacion, fecha_actualizacion
             FROM usuarios
             WHERE id_usuario = ?`,
            [userId]
        );

        console.log(`${colors.green}[ALERT] Usuario actualizado: ID ${userId} por ${req.user.nombre_usuario}${colors.reset}`);
        res.status(200).json({ mensaje: 'Usuario actualizado exitosamente', usuario: updatedUserRows[0] });

    } catch (error) {
        console.error(`${colors.red}Error al actualizar usuario:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al actualizar usuario.' });
    }
});

// Rutas de Doctores
// Obtener todos los doctores
app.get('/api/doctores', async (req, res) => {
    try {
        const [rows] = await pool.execute('SELECT id_doctor, nombre, apellido, especialidad FROM doctores');
        console.log(`${colors.blue}[INFO] Solicitud de listado de doctores.${colors.reset}`);
        res.status(200).json(rows);
    } catch (error) {
        console.error(`${colors.red}Error al obtener doctores:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al obtener doctores.' });
    }
});

// Obtener un doctor por ID
app.get('/api/doctores/:id', async (req, res) => {
    const doctorId = req.params.id;
    try {
        const [rows] = await pool.execute('SELECT id_doctor, nombre, apellido, especialidad FROM doctores WHERE id_doctor = ?', [doctorId]);
        if (rows.length === 0) {
            console.log(`${colors.yellow}[ADVERTENCIA] Doctor no encontrado para ID: ${doctorId}${colors.reset}`);
            return res.status(404).json({ error: 'Doctor no encontrado.' });
        }
        console.log(`${colors.blue}[INFO] Doctor con ID ${doctorId} solicitado.${colors.reset}`);
        res.status(200).json(rows[0]);
    } catch (error) {
        console.error(`${colors.red}Error al obtener doctor por ID:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al obtener doctor.' });
    }
});

// Agregar un nuevo doctor (solo para administradores)
app.post('/api/doctores', verifyToken, async (req, res) => {
    if (req.user.rol !== 'Administrador') {
        console.log(`${colors.red}[ACCESO DENEGADO] Intento de agregar doctor por ${req.user.nombre_usuario} (Rol: ${req.user.rol})${colors.reset}`);
        return res.status(403).json({ error: 'Acceso denegado. Solo los administradores pueden agregar doctores.' });
    }

    const { nombre, apellido, especialidad } = req.body;

    if (!nombre || !apellido || !especialidad) {
        console.log(`${colors.yellow}[VALIDACION FALLIDA] Campos de doctor incompletos. ${colors.reset}`);
        return res.status(400).json({ error: 'Nombre, apellido y especialidad del doctor son requeridos.' });
    }

    try {
        const [result] = await pool.execute('INSERT INTO doctores (nombre, apellido, especialidad) VALUES (?, ?, ?)', [nombre, apellido, especialidad]);
        console.log(`${colors.green}[ALERT] Nuevo doctor agregado: ${nombre} ${apellido} (ID: ${result.insertId}) por ${req.user.nombre_usuario}${colors.reset}`);
        res.status(201).json({ mensaje: 'Doctor agregado exitosamente', id_doctor: result.insertId, nombre, apellido, especialidad });
    } catch (error) {
        console.error(`${colors.red}Error al agregar doctor:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al agregar doctor.' });
    }
});

// Actualizar información de un doctor (solo para administradores)
app.put('/api/doctores/:id', verifyToken, async (req, res) => {
    if (req.user.rol !== 'Administrador') {
        console.log(`${colors.red}[ACCESO DENEGADO] Intento de actualizar doctor por ${req.user.nombre_usuario} (Rol: ${req.user.rol})${colors.reset}`);
        return res.status(403).json({ error: 'Acceso denegado. Solo los administradores pueden actualizar doctores.' });
    }

    const doctorId = req.params.id;
    const { nombre, apellido, especialidad } = req.body;

    if (!nombre && !apellido && !especialidad) {
        console.log(`${colors.yellow}[ADVERTENCIA] No hay datos para actualizar para el doctor ID: ${doctorId}${colors.reset}`);
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
        if (especialidad !== undefined && especialidad !== '') {
            fieldsToUpdate.push('especialidad = ?');
            updateParams.push(especialidad);
        }

        if (fieldsToUpdate.length === 0) {
            return res.status(400).json({ error: 'No hay datos válidos para actualizar.' });
        }

        updateQuery += fieldsToUpdate.join(', ') + ' WHERE id_doctor = ?';
        updateParams.push(doctorId);

        const [result] = await pool.execute(updateQuery, updateParams);

        if (result.affectedRows === 0) {
            console.log(`${colors.yellow}[ADVERTENCIA] Doctor no actualizado, posiblemente no encontrado: ID ${doctorId}${colors.reset}`);
            return res.status(404).json({ error: 'Doctor no encontrado o no se realizaron cambios.' });
        }
        console.log(`${colors.green}[ALERT] Doctor actualizado: ID ${doctorId} por ${req.user.nombre_usuario}${colors.reset}`);
        res.status(200).json({ mensaje: 'Doctor actualizado exitosamente' });

    } catch (error) {
        console.error(`${colors.red}Error al actualizar doctor:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al actualizar doctor.' });
    }
});

// Eliminar un doctor (solo para administradores)
app.delete('/api/doctores/:id', verifyToken, async (req, res) => {
    if (req.user.rol !== 'Administrador') {
        console.log(`${colors.red}[ACCESO DENEGADO] Intento de eliminar doctor por ${req.user.nombre_usuario} (Rol: ${req.user.rol})${colors.reset}`);
        return res.status(403).json({ error: 'Acceso denegado. Solo los administradores pueden eliminar doctores.' });
    }

    const doctorId = req.params.id;

    try {
        // Verificar si el doctor tiene citas asociadas
        const [citas] = await pool.execute('SELECT id_cita FROM citas WHERE id_doctor = ?', [doctorId]);
        if (citas.length > 0) {
            console.log(`${colors.yellow}[RESTRICCION] Intento de eliminar doctor ${doctorId} con citas asociadas. ${colors.reset}`);
            return res.status(400).json({ error: 'No se puede eliminar el doctor porque tiene citas asociadas.' });
        }

        // Si no tiene citas, proceder con la eliminación
        const [result] = await pool.execute('DELETE FROM doctores WHERE id_doctor = ?', [doctorId]);

        if (result.affectedRows === 0) {
            console.log(`${colors.yellow}[ADVERTENCIA] Doctor no eliminado, posiblemente no encontrado: ID ${doctorId}${colors.reset}`);
            return res.status(404).json({ error: 'Doctor no encontrado o ya eliminado.' });
        }
        console.log(`${colors.green}[ALERT] Doctor eliminado: ID ${doctorId} por ${req.user.nombre_usuario}${colors.reset}`);
        res.status(200).json({ mensaje: 'Doctor eliminado exitosamente.' });
    } catch (error) {
        console.error(`${colors.red}Error al eliminar doctor:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al eliminar doctor.' });
    }
});

// Rutas para Horarios de Doctores
// Obtener horarios de un doctor
app.get('/api/doctores/:id/horarios', async (req, res) => {
    const doctorId = req.params.id;
    const { fecha } = req.query; // Permite filtrar por fecha

    try {
        let query = 'SELECT id_horario, id_doctor, fecha, hora_inicio, hora_fin FROM horarios_doctores WHERE id_doctor = ?';
        const queryParams = [doctorId];

        if (fecha) {
            query += ' AND fecha = ?';
            queryParams.push(fecha);
        }

        const [rows] = await pool.execute(query, queryParams);
        console.log(`${colors.blue}[INFO] Horarios del doctor ${doctorId} solicitados (fecha: ${fecha || 'todas'}).${colors.reset}`);
        res.status(200).json(rows);
    } catch (error) {
        console.error(`${colors.red}Error al obtener horarios del doctor:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al obtener horarios.' });
    }
});

// Agregar un nuevo horario para un doctor (solo para administradores)
app.post('/api/horarios', verifyToken, async (req, res) => {
    if (req.user.rol !== 'Administrador') {
        console.log(`${colors.red}[ACCESO DENEGADO] Intento de agregar horario por ${req.user.nombre_usuario} (Rol: ${req.user.rol})${colors.reset}`);
        return res.status(403).json({ error: 'Acceso denegado. Solo los administradores pueden agregar horarios.' });
    }

    const { id_doctor, fecha, hora_inicio, hora_fin } = req.body;

    if (!id_doctor || !fecha || !hora_inicio || !hora_fin) {
        console.log(`${colors.yellow}[VALIDACION FALLIDA] Campos de horario incompletos. ${colors.reset}`);
        return res.status(400).json({ error: 'ID del doctor, fecha, hora de inicio y hora de fin son requeridos.' });
    }

    try {
        // Verificar si el doctor existe
        const [doctor] = await pool.execute('SELECT id_doctor FROM doctores WHERE id_doctor = ?', [id_doctor]);
        if (doctor.length === 0) {
            console.log(`${colors.yellow}[VALIDACION FALLIDA] El doctor con ID ${id_doctor} no existe. ${colors.reset}`);
            return res.status(404).json({ error: 'El doctor especificado no existe.' });
        }

        // Verificar superposición de horarios para el mismo doctor y fecha
        // Esta consulta verifica si el nuevo rango de tiempo se superpone con cualquier horario existente
        // (hora_inicio_existente < hora_fin_nueva AND hora_fin_existente > hora_inicio_nueva)
        const [existingSchedule] = await pool.execute(
            `SELECT id_horario FROM horarios_doctores
             WHERE id_doctor = ? AND fecha = ?
             AND ((hora_inicio < ? AND hora_fin > ?) OR (hora_inicio < ? AND hora_fin > ?))`,
            [id_doctor, fecha, hora_fin, hora_inicio, hora_inicio, hora_fin]
        );
        if (existingSchedule.length > 0) {
            console.log(`${colors.yellow}[VALIDACION FALLIDA] Horario superpuesto para el doctor ${id_doctor} en la fecha ${fecha}. ${colors.reset}`);
            return res.status(409).json({ error: 'Ya existe un horario que se superpone con el rango especificado para este doctor y fecha.' });
        }

        const [result] = await pool.execute('INSERT INTO horarios_doctores (id_doctor, fecha, hora_inicio, hora_fin) VALUES (?, ?, ?, ?)', [id_doctor, fecha, hora_inicio, hora_fin]);
        console.log(`${colors.green}[ALERT] Horario agregado: ID ${result.insertId} para doctor ${id_doctor} en fecha ${fecha} por ${req.user.nombre_usuario}${colors.reset}`);
        res.status(201).json({ mensaje: 'Horario agregado exitosamente', id_horario: result.insertId });

    } catch (error) {
        console.error(`${colors.red}Error al agregar horario:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al agregar horario.' });
    }
});

// Actualizar un horario (solo para administradores)
app.put('/api/horarios/:id', verifyToken, async (req, res) => {
    if (req.user.rol !== 'Administrador') {
        console.log(`${colors.red}[ACCESO DENEGADO] Intento de actualizar horario por ${req.user.nombre_usuario} (Rol: ${req.user.rol})${colors.reset}`);
        return res.status(403).json({ error: 'Acceso denegado. Solo los administradores pueden actualizar horarios.' });
    }

    const horarioId = req.params.id;
    const { fecha, hora_inicio, hora_fin } = req.body;

    if (!fecha && !hora_inicio && !hora_fin) {
        console.log(`${colors.yellow}[ADVERTENCIA] No hay datos para actualizar para el horario ID: ${horarioId}${colors.reset}`);
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
            return res.status(400).json({ error: 'No hay datos válidos para actualizar.' });
        }

        updateQuery += fieldsToUpdate.join(', ') + ' WHERE id_horario = ?';
        updateParams.push(horarioId);

        const [result] = await pool.execute(updateQuery, updateParams);

        if (result.affectedRows === 0) {
            console.log(`${colors.yellow}[ADVERTENCIA] Horario no actualizado, posiblemente no encontrado: ID ${horarioId}${colors.reset}`);
            return res.status(404).json({ error: 'Horario no encontrado o no se realizaron cambios.' });
        }
        console.log(`${colors.green}[ALERT] Horario actualizado: ID ${horarioId} por ${req.user.nombre_usuario}${colors.reset}`);
        res.status(200).json({ mensaje: 'Horario actualizado exitosamente' });

    } catch (error) {
        console.error(`${colors.red}Error al actualizar horario:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al actualizar horario.' });
    }
});

// Eliminar un horario (solo para administradores)
app.delete('/api/horarios/:id', verifyToken, async (req, res) => {
    if (req.user.rol !== 'Administrador') {
        console.log(`${colors.red}[ACCESO DENEGADO] Intento de eliminar horario por ${req.user.nombre_usuario} (Rol: ${req.user.rol})${colors.reset}`);
        return res.status(403).json({ error: 'Acceso denegado. Solo los administradores pueden eliminar horarios.' });
    }

    const horarioId = req.params.id;

    try {
        const [result] = await pool.execute('DELETE FROM horarios_doctores WHERE id_horario = ?', [horarioId]);

        if (result.affectedRows === 0) {
            console.log(`${colors.yellow}[ADVERTENCIA] Horario no eliminado, posiblemente no encontrado: ID ${horarioId}${colors.reset}`);
            return res.status(404).json({ error: 'Horario no encontrado o ya eliminado.' });
        }
        console.log(`${colors.green}[ALERT] Horario eliminado: ID ${horarioId} por ${req.user.nombre_usuario}${colors.reset}`);
        res.status(200).json({ mensaje: 'Horario eliminado exitosamente.' });
    } catch (error) {
        console.error(`${colors.red}Error al eliminar horario:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al eliminar horario.' });
    }
});

// Rutas para Citas
// Obtener todas las citas (filtrado por usuario si no es admin)
app.get('/api/citas', verifyToken, async (req, res) => {
    try {
        let query = `SELECT c.id_cita, c.id_usuario, c.id_doctor, c.fecha, c.hora, c.servicio,
                   c.tipo_agendamiento, c.estado, u.primer_nombre as nombre_paciente,
                   u.apellido_paterno as apellido_paciente, d.nombre as nombre_doctor,
                   d.apellido as apellido_doctor
            FROM citas c
            LEFT JOIN usuarios u ON c.id_usuario = u.id_usuario
            LEFT JOIN doctores d ON c.id_doctor = d.id_doctor
        `;
        const queryParams = [];

        // Si el usuario no es administrador, solo puede ver sus propias citas
        if (req.user.rol !== 'Administrador') {
            query += ' WHERE c.id_usuario = ?';
            queryParams.push(req.user.id);
            console.log(`${colors.blue}[INFO] Citas del usuario ${req.user.nombre_usuario} (ID: ${req.user.id}) solicitadas.${colors.reset}`);
        } else {
            console.log(`${colors.blue}[INFO] Todas las citas solicitadas por el administrador ${req.user.nombre_usuario}.${colors.reset}`);
        }

        const [rows] = await pool.execute(query, queryParams);
        res.status(200).json(rows);
    } catch (error) {
        console.error(`${colors.red}Error al obtener citas:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al obtener citas.' });
    }
});

// Obtener citas de un doctor específico
app.get('/api/citas/doctor/:idDoctor', verifyToken, async (req, res) => {
    const { idDoctor } = req.params;
    const { fecha } = req.query; // Permite filtrar por fecha

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
        console.log(`${colors.blue}[INFO] Citas del doctor ${idDoctor} (fecha: ${fecha || 'todas'}) solicitadas por ${req.user.nombre_usuario}.${colors.reset}`);
        res.json(rows);
    } catch (error) {
        console.error(`${colors.red}Error al obtener citas del doctor:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al obtener citas del doctor.' });
    }
});


// Función auxiliar para sumar minutos a una hora
function addMinutesToTime(timeStr, minutes) {
    const [hours, mins] = timeStr.split(':').map(Number);
    const date = new Date();
    date.setHours(hours, mins, 0, 0);
    date.setMinutes(date.getMinutes() + minutes);
    return `${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}`;
}

// Obtener horarios disponibles de un doctor
app.get('/api/doctores/:idDoctor/horarios-disponibles', verifyToken, async (req, res) => {
    const { idDoctor } = req.params;
    const { fecha } = req.query;

    if (!fecha) {
        console.log(`${colors.yellow}[VALIDACION FALLIDA] Fecha es requerida para obtener horarios disponibles. ${colors.reset}`);
        return res.status(400).json({ error: 'La fecha es un parámetro de consulta requerido.' });
    }

    try {
        // 1. Obtener los horarios configurados del doctor para la fecha dada
        const [scheduleRows] = await pool.execute(
            'SELECT id_horario, id_doctor, fecha, hora_inicio, hora_fin FROM horarios_doctores WHERE id_doctor = ? AND fecha = ?',
            [idDoctor, fecha]
        );

        if (scheduleRows.length === 0) {
            console.log(`${colors.blue}[INFO] No hay horarios configurados para el doctor ${idDoctor} en la fecha ${fecha}. ${colors.reset}`);
            return res.json([]); // No hay horarios configurados, por lo tanto no hay slots disponibles
        }

        // 2. Obtener las citas ya agendadas para el doctor en la fecha dada
        const [bookedAppointments] = await pool.execute(
            'SELECT hora FROM citas WHERE id_doctor = ? AND fecha = ? AND estado != "Cancelada" AND estado != "Completada"',
            [idDoctor, fecha]
        );
        const bookedTimes = new Set(bookedAppointments.map(app => app.hora));

        const availableSlots = [];
        const thirtyMinutesInMs = 30 * 60 * 1000; // 30 minutos en milisegundos

        const today = new Date();
        const requestedDate = new Date(fecha);
        const isToday = requestedDate.toDateString() === today.toDateString();

        scheduleRows.forEach(schedule => {
            let currentSlotStart = schedule.hora_inicio;
            while (currentSlotStart < schedule.hora_fin) {
                const currentSlotEnd = addMinutesToTime(currentSlotStart, 30);

                // Convertir a objetos Date para comparación (incluyendo la fecha)
                const slotStartDateTime = new Date(`${fecha}T${currentSlotStart}`);
                const slotEndDateTime = new Date(`${fecha}T${currentSlotEnd}`);

                // Si es hoy, no incluir slots que ya pasaron
                if (isToday && slotStartDateTime <= today) {
                    currentSlotStart = currentSlotEnd;
                    continue;
                }

                // Asegurarse de que el slot no se extienda más allá de hora_fin del horario
                if (slotEndDateTime > new Date(`${fecha}T${schedule.hora_fin}`)) {
                    break;
                }

                // Si el slot no está reservado, añadirlo a los disponibles
                if (!bookedTimes.has(currentSlotStart)) {
                    availableSlots.push(currentSlotStart);
                }
                currentSlotStart = currentSlotEnd;
            }
        });
        console.log(`${colors.blue}[INFO] Horarios disponibles para doctor ${idDoctor} en fecha ${fecha} solicitados por ${req.user.nombre_usuario}.${colors.reset}`);
        res.json(availableSlots);

    } catch (error) {
        console.error(`${colors.red}Error al obtener horarios disponibles del doctor:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al obtener horarios disponibles.' });
    }
});


// Crear una nueva cita
app.post('/api/citas', verifyToken, async (req, res) => {
    const { id_usuario, id_doctor, fecha, hora, servicio, tipo_agendamiento, estado } = req.body;

    // Campos obligatorios para crear una cita
    if (!id_doctor || !fecha || !hora || !servicio) {
        console.log(`${colors.yellow}[VALIDACION FALLIDA] Campos obligatorios de cita incompletos. ${colors.reset}`);
        return res.status(400).json({ error: 'ID del doctor, fecha, hora y servicio son requeridos.' });
    }

    // --- Validación para tipo_agendamiento (solo "Presencial") ---
    const finalTipoAgendamiento = tipo_agendamiento || 'Presencial'; // Valor por defecto
    if (finalTipoAgendamiento !== 'Presencial') {
        console.log(`${colors.red}[VALIDACION FALLIDA] Tipo de agendamiento inválido: ${tipo_agendamiento}. Solo se permite 'Presencial'. ${colors.reset}`);
        return res.status(400).json({ error: "El tipo de agendamiento debe ser 'Presencial'." });
    }

    let actualUserId = id_usuario; // Asumimos que id_usuario puede venir del body

    // Lógica para determinar el id_usuario real basado en el rol del usuario autenticado
    if (req.user.rol === 'Paciente') {
        // Un paciente solo puede agendar citas para sí mismo
        actualUserId = req.user.id;
        console.log(`${colors.blue}[INFO] Paciente ${req.user.nombre_usuario} agendando cita para sí mismo. ID: ${actualUserId}${colors.reset}`);
    } else if (req.user.rol === 'Administrador') {
        // Un administrador puede agendar para cualquier usuario, pero el id_usuario debe ser proporcionado
        if (!actualUserId) {
            console.log(`${colors.yellow}[VALIDACION FALLIDA] Un administrador debe especificar el id_usuario para agendar una cita. ${colors.reset}`);
            return res.status(400).json({ error: 'Como administrador, debe proporcionar el id_usuario para la cita.' });
        }
        console.log(`${colors.blue}[INFO] Administrador ${req.user.nombre_usuario} agendando cita para usuario ID: ${actualUserId}${colors.reset}`);
    } else {
        console.log(`${colors.red}[ACCESO DENEGADO] Rol de usuario ${req.user.rol} no tiene permiso para crear citas. ${colors.reset}`);
        return res.status(403).json({ error: 'Acceso denegado. Su rol no tiene permiso para crear citas.' });
    }

    try {
        // Validar que el paciente exista
        const [patientRows] = await pool.execute('SELECT id_usuario FROM usuarios WHERE id_usuario = ?', [actualUserId]);
        if (patientRows.length === 0) {
            console.log(`${colors.yellow}[VALIDACION FALLIDA] El paciente con ID ${actualUserId} no existe. ${colors.reset}`);
            return res.status(404).json({ error: 'El paciente especificado no existe.' });
        }

        // Validar que el doctor exista
        const [doctorRows] = await pool.execute('SELECT id_doctor FROM doctores WHERE id_doctor = ?', [id_doctor]);
        if (doctorRows.length === 0) {
            console.log(`${colors.yellow}[VALIDACION FALLIDA] El doctor con ID ${id_doctor} no existe. ${colors.reset}`);
            return res.status(404).json({ error: 'El doctor especificado no existe.' });
        }

        // Validar que el doctor tenga un horario configurado para la fecha de la cita
        const [scheduleRows] = await pool.execute(
            'SELECT hora_inicio, hora_fin FROM horarios_doctores WHERE id_doctor = ? AND fecha = ?',
            [id_doctor, fecha]
        );
        if (scheduleRows.length === 0) {
            console.log(`${colors.yellow}[VALIDACION FALLIDA] El doctor ${id_doctor} no tiene un horario configurado para la fecha ${fecha}. ${colors.reset}`);
            return res.status(400).json({ error: 'El doctor no tiene un horario configurado para esta fecha.' });
        }

        // Validar que la hora de la cita caiga dentro del horario del doctor para ese día
        const schedule = scheduleRows[0];
        const appointmentDateTime = new Date(`${fecha}T${hora}`);
        const scheduleStartDateTime = new Date(`${fecha}T${schedule.hora_inicio}`);
        const scheduleEndDateTime = new Date(`${fecha}T${schedule.hora_fin}`);

        if (appointmentDateTime < scheduleStartDateTime || appointmentDateTime >= scheduleEndDateTime) {
            console.log(`${colors.yellow}[VALIDACION FALLIDA] La hora de la cita ${hora} está fuera del horario del doctor (${schedule.hora_inicio} - ${schedule.hora_fin}) para la fecha ${fecha}. ${colors.reset}`);
            return res.status(400).json({ error: `La hora de la cita (${hora}) está fuera del horario disponible del doctor para esta fecha (${schedule.hora_inicio} - ${schedule.hora_fin}).` });
        }

        // Validar que la hora de la cita sea un slot de 30 minutos (simple verificación, no es tan robusta como la del GET)
        const [horaCitaMinutos] = hora.split(':').map(Number);
        if (horaCitaMinutos % 30 !== 0) {
            console.log(`${colors.yellow}[VALIDACION FALLIDA] La hora de la cita ${hora} no es un slot válido de 30 minutos. ${colors.reset}`);
            return res.status(400).json({ error: 'La hora de la cita debe ser un slot válido de 30 minutos (ej. 10:00, 10:30).' });
        }

        // Validar que no haya ya una cita existente para el mismo doctor, fecha y hora
        const [existingAppointments] = await pool.execute(
            `SELECT id_cita FROM citas
             WHERE id_doctor = ? AND fecha = ? AND hora = ?
             AND estado IN ('Pendiente', 'Confirmada')`, // Considerar solo citas activas
            [id_doctor, fecha, hora]
        );
        if (existingAppointments.length > 0) {
            console.log(`${colors.yellow}[VALIDACION FALLIDA] Ya existe una cita agendada para el doctor ${id_doctor} en la fecha ${fecha} a la hora ${hora}. ${colors.reset}`);
            return res.status(409).json({ error: 'Ya existe una cita agendada para este doctor en la fecha y hora seleccionadas.' });
        }

        const [result] = await pool.execute(
            `INSERT INTO citas (id_usuario, id_doctor, fecha, hora, servicio, tipo_agendamiento, estado, fecha_creacion, fecha_actualizacion)
             VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
            [actualUserId, id_doctor, fecha, hora, servicio, finalTipoAgendamiento, estado || 'Pendiente']
        );

        // Recuperar la cita recién creada con información del paciente y doctor para la respuesta
        const [newAppointment] = await pool.execute(
            `SELECT c.id_cita, c.fecha, c.hora, c.servicio, c.tipo_agendamiento, c.estado,
                    u.primer_nombre as nombre_paciente, u.apellido_paterno as apellido_paciente,
                    d.nombre as nombre_doctor, d.apellido as apellido_doctor
             FROM citas c
             JOIN usuarios u ON c.id_usuario = u.id_usuario
             JOIN doctores d ON c.id_doctor = d.id_doctor
             WHERE c.id_cita = ?`,
            [result.insertId]
        );

        console.log(`${colors.green}[ALERT] Nueva cita creada: ID ${result.insertId} para usuario ${actualUserId} con doctor ${id_doctor} en ${fecha} ${hora} por ${req.user.nombre_usuario}${colors.reset}`);
        res.status(201).json({ mensaje: 'Cita creada exitosamente', cita: newAppointment[0] });

    } catch (error) {
        console.error(`${colors.red}Error al crear cita:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al crear cita.' });
    }
});

// Actualizar una cita
app.put('/api/citas/:id', verifyToken, async (req, res) => {
    const citaId = req.params.id;
    const { fecha, hora, servicio, tipo_agendamiento, estado, id_doctor, id_usuario } = req.body;

    try {
        // Primero, verificar si la cita existe y obtener su id_usuario para la validación de permisos
        const [existingCitaRows] = await pool.execute('SELECT id_usuario, id_doctor, fecha, hora FROM citas WHERE id_cita = ?', [citaId]);
        if (existingCitaRows.length === 0) {
            console.log(`${colors.yellow}[ADVERTENCIA] Cita no encontrada para actualizar: ID ${citaId}${colors.reset}`);
            return res.status(404).json({ error: 'Cita no encontrada.' });
        }

        const existingCita = existingCitaRows[0];

        // Validar permisos: solo el propio usuario o un administrador puede actualizar la cita
        if (req.user.rol !== 'Administrador' && existingCita.id_usuario !== req.user.id) {
            console.log(`${colors.red}[ACCESO DENEGADO] Intento de actualizar cita ${citaId} no autorizado por ${req.user.nombre_usuario} (ID: ${req.user.id}, Rol: ${req.user.rol})${colors.reset}`);
            return res.status(403).json({ error: 'Acceso denegado. No tiene permisos para actualizar esta cita.' });
        }

        let updateQuery = `UPDATE citas SET `;
        const updateParams = [];
        const fieldsToUpdate = [];

        // Validar y añadir campos para actualizar
        if (id_usuario !== undefined && req.user.rol === 'Administrador') { // Solo el administrador puede cambiar el paciente de una cita
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

        // --- Validación para tipo_agendamiento (solo "Presencial" en actualización) ---
        if (tipo_agendamiento !== undefined) {
            if (tipo_agendamiento !== 'Presencial') {
                console.log(`${colors.red}[VALIDACION FALLIDA] Tipo de agendamiento inválido en actualización: ${tipo_agendamiento}. Solo se permite 'Presencial'. ${colors.reset}`);
                return res.status(400).json({ error: "El tipo de agendamiento debe ser 'Presencial'." });
            }
            fieldsToUpdate.push('tipo_agendamiento = ?');
            updateParams.push(tipo_agendamiento);
        }

        if (estado !== undefined && estado !== '') {
            fieldsToUpdate.push('estado = ?');
            updateParams.push(estado);
        }

        if (fieldsToUpdate.length === 0) {
            console.log(`${colors.yellow}[ADVERTENCIA] No hay datos para actualizar para la cita ID: ${citaId}${colors.reset}`);
            return res.status(400).json({ error: 'No hay datos para actualizar.' });
        }

        fieldsToUpdate.push('fecha_actualizacion = NOW()');

        updateQuery += fieldsToUpdate.join(', ') + ' WHERE id_cita = ?';
        updateParams.push(citaId);

        const [result] = await pool.execute(updateQuery, updateParams);

        if (result.affectedRows === 0) {
            console.log(`${colors.yellow}[ADVERTENCIA] Cita no actualizada, posiblemente no encontrada a pesar de la verificación inicial: ID ${citaId}${colors.reset}`);
            return res.status(404).json({ error: 'Cita no encontrada o no se realizaron cambios.' });
        }

        // Si se actualizó la fecha, hora o doctor, se debe revalidar la superposición (similar a POST)
        if ((fecha && fecha !== existingCita.fecha) || (hora && hora !== existingCita.hora) || (id_doctor && id_doctor !== existingCita.id_doctor)) {
            const currentDoctorId = id_doctor || existingCita.id_doctor;
            const currentFecha = fecha || existingCita.fecha;
            const currentHora = hora || existingCita.hora;

            const [scheduleRows] = await pool.execute(
                'SELECT hora_inicio, hora_fin FROM horarios_doctores WHERE id_doctor = ? AND fecha = ?',
                [currentDoctorId, currentFecha]
            );
            if (scheduleRows.length === 0) {
                // Esto podría significar que el nuevo horario es inválido o el doctor no tiene horario para la nueva fecha
                // Se podría considerar revertir la actualización o forzar un error si se cambia a un día sin horario
                console.log(`${colors.yellow}[VALIDACION DE REAGENDAMIENTO] El doctor ${currentDoctorId} no tiene un horario configurado para la fecha ${currentFecha} después de la actualización. ${colors.reset}`);
                // Para ser estricto, podríamos revertir la transacción o lanzar un error 400
                // return res.status(400).json({ error: 'El doctor no tiene un horario configurado para la nueva fecha o no es válido.' });
            } else {
                const schedule = scheduleRows[0];
                const appointmentDateTime = new Date(`${currentFecha}T${currentHora}`);
                const scheduleStartDateTime = new Date(`${currentFecha}T${schedule.hora_inicio}`);
                const scheduleEndDateTime = new Date(`${currentFecha}T${schedule.hora_fin}`);

                if (appointmentDateTime < scheduleStartDateTime || appointmentDateTime >= scheduleEndDateTime) {
                    console.log(`${colors.yellow}[VALIDACION DE REAGENDAMIENTO] La nueva hora de la cita ${currentHora} está fuera del horario del doctor (${schedule.hora_inicio} - ${schedule.hora_fin}). ${colors.reset}`);
                    return res.status(400).json({ error: `La nueva hora de la cita (${currentHora}) está fuera del horario disponible del doctor para esta fecha.` });
                }
            }

            // Validar superposición con otras citas (excluyendo la propia cita que se está actualizando)
            const [existingAppointments] = await pool.execute(
                `SELECT id_cita FROM citas
                 WHERE id_doctor = ? AND fecha = ? AND hora = ? AND id_cita != ?
                 AND estado IN ('Pendiente', 'Confirmada')`,
                [currentDoctorId, currentFecha, currentHora, citaId]
            );
            if (existingAppointments.length > 0) {
                console.log(`${colors.yellow}[VALIDACION DE REAGENDAMIENTO] La nueva hora/doctor se superpone con otra cita existente. ${colors.reset}`);
                return res.status(409).json({ error: 'La nueva fecha y hora se superponen con otra cita ya agendada para este doctor.' });
            }
        }


        // Obtener la cita actualizada con información del paciente y doctor para la respuesta
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

        console.log(`${colors.green}[ALERT] Cita actualizada: ID ${citaId} por ${req.user.nombre_usuario}${colors.reset}`);
        res.status(200).json({ mensaje: 'Cita actualizada exitosamente', cita: updatedCitaRows[0] });

    } catch (error) {
        console.error(`${colors.red}Error al actualizar cita:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al actualizar cita.' });
    }
});

// Eliminar una cita
app.delete('/api/citas/:id', verifyToken, async (req, res) => {
    const citaId = req.params.id;

    try {
        // Verificar si la cita existe y obtener su id_usuario para la validación de permisos
        const [existingCitaRows] = await pool.execute('SELECT id_usuario FROM citas WHERE id_cita = ?', [citaId]);
        if (existingCitaRows.length === 0) {
            console.log(`${colors.yellow}[ADVERTENCIA] Cita no encontrada para eliminar: ID ${citaId}${colors.reset}`);
            return res.status(404).json({ error: 'Cita no encontrada.' });
        }

        const existingCita = existingCitaRows[0];

        // Validar permisos: solo el propio usuario o un administrador puede eliminar la cita
        if (req.user.rol !== 'Administrador' && existingCita.id_usuario !== req.user.id) {
            console.log(`${colors.red}[ACCESO DENEGADO] Intento de eliminar cita ${citaId} no autorizado por ${req.user.nombre_usuario} (ID: ${req.user.id}, Rol: ${req.user.rol})${colors.reset}`);
            return res.status(403).json({ error: 'Acceso denegado. No tiene permisos para eliminar esta cita.' });
        }

        const [result] = await pool.execute('DELETE FROM citas WHERE id_cita = ?', [citaId]);

        if (result.affectedRows === 0) {
            console.log(`${colors.yellow}[ADVERTENCIA] Cita no eliminada, posiblemente no encontrada a pesar de la verificación inicial: ID ${citaId}${colors.reset}`);
            return res.status(404).json({ error: 'Cita no encontrada o ya eliminada.' });
        }
        console.log(`${colors.green}[ALERT] Cita eliminada: ID ${citaId} por ${req.user.nombre_usuario}${colors.reset}`);
        res.status(200).json({ mensaje: 'Cita eliminada exitosamente.' });
    } catch (error) {
        console.error(`${colors.red}Error al eliminar cita:`, error, `${colors.reset}`);
        res.status(500).json({ error: 'Error interno del servidor al eliminar la cita.' });
    }
});


// Ruta de prueba
app.get('/', (req, res) => {
    res.send('API de Citas Médicas funcionando!');
});

// Inicio del servidor
app.listen(PORT, () => {
    console.log(`${colors.cyan}Servidor ejecutándose en el puerto ${PORT}${colors.reset}`);
});