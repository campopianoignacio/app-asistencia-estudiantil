// 1. Importar paquetes
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken'); // Importamos la librería para JSON Web Tokens

// 2. Crear una instancia de Express
const app = express();

// --- Middlewares ---
app.use(cors());
app.use(express.json());

// --- Configuración ---
const PORT = 3000;
// Este es un "secreto" para firmar nuestros tokens. En una app real, debería estar en una variable de entorno y ser mucho más complejo.
const JWT_SECRET = 'una-clave-secreta-muy-dificil-de-adivinar';

// --- Base de datos en memoria (temporal) ---
// Ahora cada usuario tendrá su propia propiedad 'data' para guardar sus estudiantes y asistencias.
const users = [];

// ===================================================================================
// RUTAS DE LA API
// ===================================================================================

app.get('/', (req, res) => {
  res.send('¡El backend está funcionando con autenticación JWT!');
});

// --- Rutas de Autenticación ---

app.post('/register', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'El email y la contraseña son requeridos.' });
  if (users.find(user => user.email === email)) return res.status(400).json({ message: 'El email ya está registrado.' });
  
  const newUser = {
    id: users.length + 1,
    email,
    password, // En una app real, esto debería estar "hasheado" con bcrypt
    data: { students: [], attendance: {} } // Cada usuario empieza con datos vacíos
  };
  users.push(newUser);
  
  console.log('Usuario registrado:', newUser);
  res.status(201).json({ message: 'Usuario registrado con éxito.' });
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'El email y la contraseña son requeridos.' });

  const user = users.find(u => u.email === email);
  if (!user || user.password !== password) return res.status(401).json({ message: 'Email o contraseña incorrectos.' });

  // Si el login es correcto, creamos un token JWT
  // El token contiene el ID del usuario, que nos servirá para identificarlo en futuras peticiones.
  const accessToken = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '8h' }); // El token expira en 8 horas

  res.json({ accessToken: accessToken }); // Enviamos el token al cliente
});

// --- Middleware de Autenticación ---
// Esta función actuará como un "guardia de seguridad" para nuestras rutas.
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Formato: "Bearer TOKEN"

  if (token == null) return res.sendStatus(401); // No hay token, no autorizado

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // El token no es válido o ha expirado
    req.user = user; // Guardamos la información del usuario (el payload del token) en el objeto request
    next(); // Si todo está bien, continuamos a la ruta solicitada
  });
}

// --- Rutas de Datos (Protegidas) ---

// Ruta para OBTENER los datos del usuario que ha iniciado sesión
app.get('/api/data', authenticateToken, (req, res) => {
  // Gracias al middleware, ahora tenemos req.user.id con el ID del usuario
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).send('Usuario no encontrado.');

  console.log(`Enviando datos para el usuario ${user.email}`);
  res.json(user.data);
});

// Ruta para GUARDAR los datos del usuario que ha iniciado sesión
app.post('/api/data', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).send('Usuario no encontrado.');

  // Reemplazamos los datos antiguos del usuario con los nuevos que vienen en el cuerpo de la petición
  user.data = req.body;
  console.log(`Datos guardados para el usuario ${user.email}`);
  res.status(200).send('Datos guardados con éxito.');
});


// 5. Iniciar el servidor
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});