import express from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import morgan from 'morgan';
import { verificarCredenciales, registrarUsuario } from './consultas.js';


const app = express();
const PORT = 3000;
const SECRET_KEY = 'mi_llave_secreta';

app.use(express.json());
app.use(morgan('dev'));

app.post('/usuarios', async (req, res) => {
  try {
    const usuario = req.body;
    await registrarUsuario(usuario);
    res.status(201).send('Usuario creado con éxito');
  } catch (error) {
    res.status(500).send(error);
  }
});


app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    await verificarCredenciales(email, password);
    const token = jwt.sign({ email }, SECRET_KEY, { expiresIn: '1h' });
    res.send(token);
  } catch (error) {
    res.status(error.code || 500).send(error);
  }
});


const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token requerido' });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token inválido' });
    req.user = user;
    next();
  });
};


app.get('/usuarios', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [req.user.email]);
    const user = result.rows[0];
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener el usuario' });
  }
});


app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});