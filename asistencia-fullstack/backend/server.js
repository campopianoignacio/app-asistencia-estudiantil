// 1. Importar paquetes
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

// 2. Crear una instancia de Express
const app = express();

// --- Middlewares ---
app.use(cors());
app.use(express.json());

// --- Configuración ---
const PORT = 3000;
const JWT_SECRET = 'una-clave-secreta-muy-dificil-de-adivinar';
// IMPORTANTE: Reemplaza la siguiente URL con la URL de conexión de tu base de datos de MongoDB Atlas
const MONGO_URI = 'mongodb+srv://ignaciocampopiano_db_user:JcqS2FL4F3LE7aH6@cluster0.vqdvyrq.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';

// --- Conexión a la Base de Datos ---
mongoose.connect(MONGO_URI)
  .then(() => console.log('Conectado a MongoDB Atlas'))
  .catch(err => console.error('Error al conectar a MongoDB:', err));

// --- Esquema y Modelo de Usuario ---
const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  data: {
    students: { type: Array, default: [] },
    attendance: { type: Object, default: {} },
    courses: { type: Array, default: [] }
  }
});

const User = mongoose.model('User', UserSchema);

// ===================================================================================
// RUTAS DE LA API
// ===================================================================================

app.get('/', (req, res) => {
  res.send('¡El backend está funcionando con autenticación JWT y persistencia en MongoDB!');
});

// --- Rutas de Autenticación ---

app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'El email y la contraseña son requeridos.' });

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'El email ya está registrado.' });

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      email,
      password: hashedPassword,
      data: { students: [], attendance: {}, courses: [] }
    });

    await newUser.save();
    
    console.log('Usuario registrado:', email);
    res.status(201).json({ message: 'Usuario registrado con éxito.' });
  } catch (error) {
    console.error('Error en el registro:', error);
    res.status(500).json({ message: 'Error en el servidor al intentar registrar.' });
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'El email y la contraseña son requeridos.' });

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: 'Email o contraseña incorrectos.' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: 'Email o contraseña incorrectos.' });

    const accessToken = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '8h' });

    res.json({ accessToken: accessToken });
  } catch (error) {
    console.error('Error en el login:', error);
    res.status(500).json({ message: 'Error en el servidor al intentar iniciar sesión.' });
  }
});

// --- Middleware de Autenticación ---
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.sendStatus(403);
    req.userId = decoded.id;
    next();
  });
}

// --- Rutas de Datos (Protegidas) ---

app.get('/api/data', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).send('Usuario no encontrado.');

    console.log(`Enviando datos para el usuario ${user.email}`);
    res.json(user.data);
  } catch (error) {
    console.error('Error al obtener datos:', error);
    res.status(500).json({ message: 'Error en el servidor al obtener datos.' });
  }
});

app.post('/api/data', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).send('Usuario no encontrado.');

    user.data = req.body;
    await user.save();
    
    console.log(`Datos guardados para el usuario ${user.email}`);
    res.status(200).send('Datos guardados con éxito.');
  } catch (error) {
    console.error('Error al guardar datos:', error);
    res.status(500).json({ message: 'Error en el servidor al guardar datos.' });
  }
});


// 5. Iniciar el servidor
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});