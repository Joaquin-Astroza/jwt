import pkg from 'pg';
import bcrypt from 'bcryptjs';
const { Pool } = pkg;

const pool = new Pool({
  user: 'tu_usuario',
  host: 'localhost',
  database: 'softjobs',
  password: 'root',
  port: 5432,
});

export const registrarUsuario = async (usuario) => {
  try {
    let { email, password } = usuario;
    const passwordEncriptada = bcrypt.hashSync(password);
    password = passwordEncriptada;
    const values = [email, passwordEncriptada];
    const consulta = "INSERT INTO usuarios VALUES (DEFAULT, $1, $2)";
    await pool.query(consulta, values);
  } catch (error) {
    throw { code: 500, message: "Error al registrar el usuario" };
  }
};

export const verificarCredenciales = async (email, password) => {
  try {
    const values = [email];
    const consulta = "SELECT * FROM usuarios WHERE email = $1";
    const { rows: [usuario], rowCount } = await pool.query(consulta, values);

    if (!rowCount || !bcrypt.compareSync(password, usuario.password)) {
      throw { code: 401, message: "Email o contraseña incorrecta" };
    }
  } catch (error) {
    throw { code: error.code || 500, message: error.message || "Error al verificar credenciales" };
  }
};

export { pool };