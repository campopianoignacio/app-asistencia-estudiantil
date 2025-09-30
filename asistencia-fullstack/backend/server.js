// 1. Importar paquetes
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

// 2. Crear una instancia de Express
const app = express();

// --- Middlewares ---
app.use(cors());
app.use(express.json());

// --- Configuración ---
const PORT = 3000;
const JWT_SECRET = 'una-clave-secreta-muy-dificil-de-adivinar';

// --- Base de Datos Persistente (archivo JSON) ---
const DB_PATH = path.join(__dirname, 'db.json');
let users = [];

function loadDatabase() {
  try {
    if (fs.existsSync(DB_PATH)) {
      const data = fs.readFileSync(DB_PATH, 'utf8');
      users = JSON.parse(data);
      console.log('Base de datos cargada correctamente.');
    } else {
      console.log('No se encontró db.json. Se creará uno nuevo al guardar datos.');
    }
  } catch (error) {
    console.error('Error al cargar la base de datos:', error);
  }
}

function saveDatabase() {
  try {
    fs.writeFileSync(DB_PATH, JSON.stringify(users, null, 2), 'utf8');
    console.log('Base de datos guardada correctamente.');
  } catch (error) {
    console.error('Error al guardar la base de datos:', error);
  }
}

// ===================================================================================
// RUTAS DE LA API
// ===================================================================================

app.get('/', (req, res) => {
  res.send('¡El backend está funcionando con autenticación JWT y persistencia de datos!');
});

// --- Rutas de Autenticación ---

app.post('/register', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'El email y la contraseña son requeridos.' });
  if (users.find(user => user.email === email)) return res.status(400).json({ message: 'El email ya está registrado.' });
  
  const newUser = {
    id: users.length > 0 ? Math.max(...users.map(u => u.id)) + 1 : 1,
    email,
    password, // En una app real, esto debería estar "hasheado" con bcrypt
    data: { students: [], attendance: {}, courses: [] }
  };
  users.push(newUser);
  saveDatabase(); // Guardar en el archivo
  
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
  saveDatabase(); // Guardar en el archivo
  console.log(`Datos guardados para el usuario ${user.email}`);
  res.status(200).send('Datos guardados con éxito.');
});


// 5. Iniciar el servidor
app.listen(PORT, () => {
  loadDatabase(); // Cargar la base de datos al iniciar
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
