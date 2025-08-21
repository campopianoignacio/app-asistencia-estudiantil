const functions = require("firebase-functions");
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");

const app = express();

// --- Middlewares ---
// Usamos cors con origin=true para que la función permita peticiones
// desde tu dominio de Firebase Hosting una vez desplegado.
app.use(cors({ origin: true }));
app.use(express.json());

// --- Configuración ---
// En un entorno real, esto debería ser una variable de configuración de Firebase
// con `firebase functions:config:set secret.key="YOUR_SECRET_KEY"`
const JWT_SECRET = 'una-clave-secreta-muy-dificil-de-adivinar';

// --- Base de datos en memoria (temporal) ---
const users = [];

// ===================================================================================
// RUTAS DE LA API (idénticas a tu server.js)
// ===================================================================================

app.get('/', (req, res) => {
  res.send('¡El backend de Firebase está funcionando con autenticación JWT!');
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
    data: { students: [], attendance: {} }
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

  const accessToken = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '8h' });
  res.json({ accessToken: accessToken });
});

// --- Middleware de Autenticación ---
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// --- Rutas de Datos (Protegidas) ---

app.get('/api/data', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).send('Usuario no encontrado.');

  console.log(`Enviando datos para el usuario ${user.email}`);
  res.json(user.data);
});

app.post('/api/data', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).send('Usuario no encontrado.');

  user.data = req.body;
  console.log(`Datos guardados para el usuario ${user.email}`);
  res.status(200).send('Datos guardados con éxito.');
});

// ===================================================================================
// Exportar la App de Express como una Cloud Function
// ===================================================================================
// En lugar de app.listen, exportamos la app para que Firebase la pueda ejecutar.
// La función se llamará 'api'.
exports.api = functions.https.onRequest(app);
