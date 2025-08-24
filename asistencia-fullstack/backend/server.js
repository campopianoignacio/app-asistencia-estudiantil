// 1. Importar paquetes
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { MongoClient, ObjectId } = require('mongodb'); // Importamos MongoClient y ObjectId
const bcrypt = require('bcrypt'); // Importamos bcrypt

// 2. Crear una instancia de Express
const app = express();

// --- Middlewares ---
app.use(cors());
app.use(express.json());

// --- Configuración ---
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'una-clave-secreta-muy-dificil-de-adivinar'; // En una app real, esto debería estar en una variable de entorno.

// --- Conexión a la Base de Datos ---
const MONGO_URI = "mongodb+srv://campopianoignacio:a2e3YivyVBnhg@cluster0.ak3l55y.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";
const client = new MongoClient(MONGO_URI);

let db;
let usersCollection;

async function connectDB() {
  try {
    await client.connect();
    db = client.db('asistencia-app'); // Puedes nombrar tu base de datos como quieras
    usersCollection = db.collection('users');
    console.log("Conectado a MongoDB Atlas");
  } catch (error) {
    console.error("No se pudo conectar a MongoDB Atlas", error);
    process.exit(1);
  }
}

// ===================================================================================
// RUTAS DE LA API
// ===================================================================================

app.get('/', (req, res) => {
  res.send('¡El backend está funcionando con MongoDB y JWT!');
});

// --- Rutas de Autenticación ---

app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'El email y la contraseña son requeridos.' });

  try {
    const existingUser = await usersCollection.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'El email ya está registrado.' });

    // Encriptamos la contraseña
    const hashedPassword = await bcrypt.hash(password, 10); // 10 es el "salt rounds"

    const newUser = {
      email,
      password: hashedPassword,
      data: { students: [], attendance: {} }
    };
    
    await usersCollection.insertOne(newUser);
    
    console.log('Usuario registrado:', email);
    res.status(201).json({ message: 'Usuario registrado con éxito.' });
  } catch (error) {
    console.error("Error en el registro:", error);
    res.status(500).json({ message: "Error interno del servidor." });
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'El email y la contraseña son requeridos.' });

  try {
    const user = await usersCollection.findOne({ email });
    if (!user) return res.status(401).json({ message: 'Email o contraseña incorrectos.' });

    // Comparamos la contraseña enviada con la hasheada en la BD
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: 'Email o contraseña incorrectos.' });

    // Si el login es correcto, creamos un token JWT
    const accessToken = jwt.sign({ id: user._id.toString() }, JWT_SECRET, { expiresIn: '8h' });

    res.json({ accessToken: accessToken });
  } catch (error) {
    console.error("Error en el login:", error);
    res.status(500).json({ message: "Error interno del servidor." });
  }
});

// --- Middleware de Autenticación ---
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, decoded) => { // 'decoded' es el payload del token
    if (err) return res.sendStatus(403);
    req.userId = decoded.id; // Guardamos el ID del usuario en el objeto request
    next();
  });
}

// --- Rutas de Datos (Protegidas) ---

app.get('/api/data', authenticateToken, async (req, res) => {
  try {
    const user = await usersCollection.findOne({ _id: new ObjectId(req.userId) });
    if (!user) return res.status(404).send('Usuario no encontrado.');

    console.log(`Enviando datos para el usuario ${user.email}`);
    res.json(user.data);
  } catch (error) {
    console.error("Error obteniendo datos:", error);
    res.status(500).json({ message: "Error interno del servidor." });
  }
});

app.post('/api/data', authenticateToken, async (req, res) => {
  try {
    const result = await usersCollection.updateOne(
      { _id: new ObjectId(req.userId) },
      { $set: { data: req.body } }
    );

    if (result.matchedCount === 0) return res.status(404).send('Usuario no encontrado.');
    
    console.log(`Datos guardados para el usuario con ID ${req.userId}`);
    res.status(200).send('Datos guardados con éxito.');
  } catch (error) {
    console.error("Error guardando datos:", error);
    res.status(500).json({ message: "Error interno del servidor." });
  }
});


// 5. Iniciar el servidor y conectar a la BD
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
  connectDB();
});
