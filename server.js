// ----------------------------------------------------------------------
// server.js - Back-End Olimpollo (VERSIÓN MAESTRA FINAL - CORREGIDA)
// ----------------------------------------------------------------------

const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors'); 
const { Pool } = require('pg'); 
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;

// Configuración JWT (En producción usar variables de entorno)
const JWT_SECRET = process.env.JWT_SECRET || 'miclavesecretaultraseguraolimpollos';


// ======================================================================
// 1. CONFIGURACIÓN DE LA BASE DE DATOS (POSTGRESQL)
// ======================================================================
const isProduction = process.env.NODE_ENV === 'production';

const connectionString = `postgresql://${process.env.DB_USER}:${process.env.DB_PASSWORD}@${process.env.DB_HOST}/${process.env.DB_DATABASE}`;

const pool = new Pool({
    connectionString: isProduction ? process.env.DATABASE_URL : connectionString,
    ssl: isProduction ? { rejectUnauthorized: false } : false
});

// Verificación de conexión al iniciar
pool.query('SELECT NOW()', (err, res) => {
    if (err) {
        console.error('Error crítico: No se pudo conectar a la base de datos.', err);
    } else {
        console.log('✅ Conexión exitosa a PostgreSQL establecida.');
    }
});


// ======================================================================
// 2. MIDDLEWARES
// ======================================================================
app.use(cors());
app.use(bodyParser.json());

// Rutas que no requieren sesión (login y el menú público del QR digital)
const RUTAS_PUBLICAS = [
    { method: 'POST', path: '/api/login' },
    { method: 'GET', path: '/api/menu/pos' },
];

function verifyToken(req, res, next) {
    const esPublica = RUTAS_PUBLICAS.some(r => r.method === req.method && r.path === req.path);
    if (esPublica) return next();

    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Acceso denegado. Token requerido.' });

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Sesión inválida o expirada.' });
        req.user = decoded;
        next();
    });
}

function requireAdmin(req, res, next) {
    if (req.user?.rol !== 'Administrador') return res.status(403).json({ error: 'Acceso solo para Administradores.' });
    next();
}

app.use(verifyToken);


// ======================================================================
// 3. AUTENTICACIÓN Y USUARIOS
// ======================================================================

// Login
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT id, password_hash, rol FROM Usuarios WHERE username = $1', [username]);
        
        if (result.rows.length === 0) return res.status(401).json({ error: 'Credenciales inválidas.' });

        const user = result.rows[0];
        const match = await bcrypt.compare(password, user.password_hash);
        
        if (!match) return res.status(401).json({ error: 'Credenciales inválidas.' });

        const token = jwt.sign({ userId: user.id, username: username, rol: user.rol }, JWT_SECRET, { expiresIn: '12h' });
        res.status(200).json({ token, rol: user.rol, mensaje: 'Bienvenido.' });
    } catch (err) {
        res.status(500).json({ error: 'Error de servidor.' });
    }
});

// Listar Usuarios
app.get('/api/usuarios', requireAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, username, rol FROM Usuarios ORDER BY id');
        res.status(200).json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Crear Usuario
app.post('/api/usuarios', requireAdmin, async (req, res) => {
    const { username, password, rol } = req.body;
    try {
        const existing = await pool.query('SELECT id FROM Usuarios WHERE username = $1', [username]);
        if (existing.rows.length > 0) return res.status(400).json({ error: 'El usuario ya existe.' });

        const hash = await bcrypt.hash(password, 10);
        const result = await pool.query('INSERT INTO Usuarios (username, password_hash, rol) VALUES ($1, $2, $3) RETURNING id, username, rol', [username, hash, rol]);
        res.status(201).json(result.rows[0]); 
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Editar Usuario (rol y/o contraseña)
app.put('/api/usuarios/:id', requireAdmin, async (req, res) => {
    const { rol, password } = req.body;
    if (!rol) return res.status(400).json({ error: 'El rol es obligatorio.' });
    try {
        let result;
        if (password) {
            const hash = await bcrypt.hash(password, 10);
            result = await pool.query(
                'UPDATE Usuarios SET rol = $1, password_hash = $2 WHERE id = $3 RETURNING id, username, rol',
                [rol, hash, req.params.id]
            );
        } else {
            result = await pool.query(
                'UPDATE Usuarios SET rol = $1 WHERE id = $2 RETURNING id, username, rol',
                [rol, req.params.id]
            );
        }
        if (result.rowCount === 0) return res.status(404).json({ error: 'Usuario no encontrado.' });
        res.status(200).json(result.rows[0]);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Eliminar Usuario
app.delete('/api/usuarios/:id', requireAdmin, async (req, res) => {
    if (parseInt(req.params.id) === 1) return res.status(403).json({ error: 'No se puede eliminar al Super Admin.' });
    try {
        const result = await pool.query('DELETE FROM Usuarios WHERE id = $1 RETURNING id', [req.params.id]);
        if (result.rowCount === 0) return res.status(404).json({ error: 'Usuario no encontrado.' });
        res.status(204).send(); 
    } catch (err) { res.status(500).json({ error: err.message }); }
});


// ======================================================================
// 4. GESTIÓN DEL MENÚ (POS Y CRUD)
// ======================================================================

// Obtener Menú Completo para el POS (Estructura Anidada)
app.get('/api/menu/pos', async (req, res) => {
    try {
        // AÑADIDO: imagen_url
        const prodRes = await pool.query('SELECT id, nombre_venta, categoria, CAST(precio_base AS TEXT) AS precio_base, grupos_modificadores, imagen_url FROM menu_productos ORDER BY categoria, nombre_venta');
        const opRes = await pool.query('SELECT id, nombre_opcion, valor, CAST(precio_adicional AS TEXT) AS precio_adicional FROM menu_opciones ORDER BY nombre_opcion, valor');

        const opciones = opRes.rows.reduce((acc, op) => {
            if (!acc[op.nombre_opcion]) acc[op.nombre_opcion] = [];
            op.precio_adicional = parseFloat(op.precio_adicional); 
            acc[op.nombre_opcion].push(op);
            return acc;
        }, {});

        const productos = prodRes.rows.map(p => ({ ...p, precio_base: parseFloat(p.precio_base) }));
        res.status(200).json({ productos, opciones });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// CRUD Productos
app.get('/api/menu/productos', async (req, res) => {
    try {
        // Agregamos imagen_url a la consulta
        const result = await pool.query('SELECT id, nombre_venta, categoria, receta_id, imagen_url FROM menu_productos ORDER BY nombre_venta');
        res.status(200).json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/menu/productos', async (req, res) => {
    const { nombre_venta, precio_base, categoria, receta_id, descripcion, grupos_modificadores, imagen_url } = req.body;
    try {
        const result = await pool.query(`INSERT INTO menu_productos (nombre_venta, precio_base, categoria, receta_id, descripcion, grupos_modificadores, imagen_url) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`, 
            [nombre_venta, parseFloat(precio_base), categoria, receta_id || null, descripcion, grupos_modificadores || '', imagen_url || null]);
        res.status(201).json(result.rows[0]);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/menu/productos/:id', async (req, res) => {
    const { nombre_venta, precio_base, categoria, receta_id, descripcion, grupos_modificadores, imagen_url } = req.body;
    try {
        const result = await pool.query(`UPDATE menu_productos SET nombre_venta=$1, precio_base=$2, categoria=$3, receta_id=$4, descripcion=$5, grupos_modificadores=$6, imagen_url=$7 WHERE id=$8 RETURNING *`, 
            [nombre_venta, parseFloat(precio_base), categoria, receta_id || null, descripcion, grupos_modificadores || '', imagen_url || null, req.params.id]);
        if (result.rowCount === 0) return res.status(404).json({ error: 'No encontrado' });
        res.status(200).json(result.rows[0]);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/menu/productos/:id', async (req, res) => {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        // 1. Desvinculamos el producto de los tickets históricos para no perder la contabilidad
        await client.query('UPDATE pedido_items SET menu_producto_id = NULL WHERE menu_producto_id = $1', [req.params.id]);
        
        // 2. Ahora sí, borramos el platillo del menú permanentemente
        await client.query('DELETE FROM menu_productos WHERE id = $1', [req.params.id]);
        
        await client.query('COMMIT');
        res.status(204).send();
    } catch (err) { 
        await client.query('ROLLBACK');
        res.status(500).json({ error: err.message }); 
    } finally {
        client.release();
    }
});

// CRUD Opciones (Modificadores)
app.get('/api/menu/opciones', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM menu_opciones WHERE nombre_opcion = $1 ORDER BY id', [req.query.nombre_opcion || 'Salsa']);
        res.status(200).json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/menu/opciones', async (req, res) => {
    try {
        const { nombre_opcion, valor, precio_adicional, insumo_id, cantidad_insumo } = req.body;
        const result = await pool.query(
            'INSERT INTO menu_opciones (nombre_opcion, valor, precio_adicional, insumo_id, cantidad_insumo) VALUES ($1, $2, $3, $4, $5) RETURNING *', 
            [nombre_opcion, valor, parseFloat(precio_adicional) || 0, insumo_id || null, parseFloat(cantidad_insumo) || 0]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/menu/opciones/:id', async (req, res) => {
    try {
        await pool.query('DELETE FROM menu_opciones WHERE id = $1', [req.params.id]);
        res.status(204).send();
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/menu/opciones/grupo/:nombre', async (req, res) => {
    try {
        await pool.query('DELETE FROM menu_opciones WHERE nombre_opcion = $1', [req.params.nombre]);
        res.status(200).json({ mensaje: 'Grupo eliminado' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});


// ======================================================================
// 5. INVENTARIO Y COMPRAS (CORREGIDO CON PROVEEDORES)
// ======================================================================

// Listar Inventario (Filtros)
app.get('/api/inventario', async (req, res) => {
    const { categoria, estado } = req.query;
    let clauses = [], values = [], idx = 1;

    if (categoria) { clauses.push(`categoria = $${idx++}`); values.push(categoria); }
    if (estado) {
        if (estado === 'Agotado') clauses.push(`cantidad <= 0`);
        else if (estado === 'Requiere re-stock') clauses.push(`(cantidad > 0 AND cantidad <= stock_minimo)`);
        else if (estado === 'En stock') clauses.push(`cantidad > stock_minimo`);
    }
    
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    
    // CORRECCIÓN: Agregamos 'proveedor_preferido' a la selección
    const query = `
        SELECT id, nombre, cantidad, unidad, stock_minimo, categoria, proveedor_preferido,
        CASE WHEN cantidad <= 0 THEN 'Agotado' WHEN cantidad <= stock_minimo THEN 'Requiere re-stock' ELSE 'En stock' END AS estado
        FROM Insumos ${where} ORDER BY id;`;

    try {
        const result = await pool.query(query, values);
        res.status(200).json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Crear Insumo
app.post('/api/inventario', async (req, res) => {
    // CORRECCIÓN: Recibimos proveedor_preferido
    const { nombre, cantidad, unidad, stock_minimo, categoria, proveedor_preferido } = req.body;
    try {
        // CORRECCIÓN: Agregamos el campo al INSERT
        const result = await pool.query(
            'INSERT INTO Insumos (nombre, cantidad, unidad, stock_minimo, categoria, proveedor_preferido) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *', 
            [nombre, parseInt(cantidad), unidad, parseInt(stock_minimo), categoria, proveedor_preferido || 'General']
        );
        res.status(201).json(result.rows[0]);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Editar Insumo
app.put('/api/inventario/:id', async (req, res) => {
    // CORRECCIÓN: Recibimos proveedor_preferido
    const { nombre, cantidad, unidad, stock_minimo, categoria, proveedor_preferido } = req.body;
    try {
        // CORRECCIÓN: Agregamos el campo al UPDATE ($6)
        const result = await pool.query(
            'UPDATE Insumos SET nombre=$1, cantidad=$2, unidad=$3, stock_minimo=$4, categoria=$5, proveedor_preferido=$6 WHERE id=$7 RETURNING *',
            [nombre, parseInt(cantidad), unidad, parseInt(stock_minimo), categoria, proveedor_preferido || 'General', req.params.id]
        );
        res.status(200).json(result.rows[0]);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Eliminar Insumo
app.delete('/api/inventario/:id', async (req, res) => {
    try {
        await pool.query('DELETE FROM Insumos WHERE id = $1', [req.params.id]);
        res.status(204).send();
    } catch (err) { 
        if(err.code === '23503') return res.status(409).json({ error: 'Este insumo está vinculado a una receta activa.' });
        res.status(500).json({ error: err.message }); 
    }
});

// Guardar Histórico (Cierre de día)
app.post('/api/inventario/guardar', async (req, res) => {
    try {
        await pool.query(`INSERT INTO Registro_Inventario (insumo_id, nombre_insumo, cantidad_registrada, unidad_medida, categoria)
            SELECT id, nombre, cantidad, unidad, categoria FROM Insumos`);
        res.status(201).json({ mensaje: 'Inventario registrado.' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Registrar Compra (Suma Stock + Promedia Costo)
app.post('/api/compras', async (req, res) => {
    const { proveedor, items, total_compra } = req.body;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const compraRes = await client.query('INSERT INTO compras (proveedor, total_compra) VALUES ($1, $2) RETURNING id', [proveedor || 'General', total_compra]);
        const compraId = compraRes.rows[0].id;

        for (const item of items) {
            const { insumo_id, cantidad, costo_unitario } = item;
            await client.query(`INSERT INTO compra_items (compra_id, insumo_id, cantidad_comprada, costo_unitario, subtotal) VALUES ($1, $2, $3, $4, $5)`,
                [compraId, insumo_id, cantidad, costo_unitario, cantidad * costo_unitario]);
            
            // Lógica de Costo Promedio Ponderado
            const insumo = await client.query('SELECT cantidad, costo_promedio FROM insumos WHERE id = $1', [insumo_id]);
            if (insumo.rows.length > 0) {
                const stock = parseFloat(insumo.rows[0].cantidad);
                const costo = parseFloat(insumo.rows[0].costo_promedio) || 0;
                const nuevoStock = stock + parseFloat(cantidad);
                let nuevoCosto = costo_unitario;
                if (nuevoStock > 0) nuevoCosto = ((stock * costo) + (cantidad * costo_unitario)) / nuevoStock;
                
                await client.query('UPDATE insumos SET cantidad = $1, costo_promedio = $2 WHERE id = $3', [nuevoStock, nuevoCosto, insumo_id]);
            }
        }
        await client.query('COMMIT');
        res.status(201).json({ mensaje: 'Compra registrada' });
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(500).json({ error: err.message });
    } finally { client.release(); }
});


// ======================================================================
// 6. GESTIÓN DE PEDIDOS (CORE)
// ======================================================================

const TASA_COMISION = { 'Tarjeta': 0.04176, 'Aplicación': 0.4213 };

// Resuelve método de pago + comisión a partir del body de POST/PUT /api/pedidos.
// Para pago mixto (Efectivo + un método más) valida que los montos cuadren con el total
// y calcula la comisión solo sobre la parte no-efectivo. Lanza Error en datos inválidos.
function resolverPago(body, total_ajustado) {
    const { metodo_pago, metodo_pago_secundario, monto_efectivo, monto_no_efectivo } = body;

    if (metodo_pago === 'Mixto') {
        if (!metodo_pago_secundario || metodo_pago_secundario === 'Efectivo') {
            throw new Error('Para un pago mixto indica un método secundario distinto de Efectivo.');
        }
        const efectivo = parseFloat(monto_efectivo);
        const noEfectivo = parseFloat(monto_no_efectivo);
        if (isNaN(efectivo) || isNaN(noEfectivo) || efectivo < 0 || noEfectivo < 0) {
            throw new Error('Montos de pago mixto inválidos.');
        }
        if (Math.abs((efectivo + noEfectivo) - total_ajustado) > 0.01) {
            throw new Error('La suma del pago mixto no coincide con el total del pedido.');
        }
        return {
            metodo_pago: 'Mixto',
            metodo_pago_secundario,
            monto_efectivo: efectivo,
            monto_no_efectivo: noEfectivo,
            comision: (TASA_COMISION[metodo_pago_secundario] || 0) * noEfectivo
        };
    }

    const metodo = metodo_pago || 'Efectivo';
    return {
        metodo_pago: metodo,
        metodo_pago_secundario: null,
        monto_efectivo: null,
        monto_no_efectivo: null,
        comision: (TASA_COMISION[metodo] || 0) * total_ajustado
    };
}

app.get('/api/pedidos', async (req, res) => {
    await pool.query(`UPDATE pedidos SET estado = 'Entregado' WHERE estado = 'Pendiente' AND eliminado = FALSE AND fecha_creacion < NOW() - INTERVAL '2 hours'`);

    const { canal, estado, fechaInicio, fechaFin } = req.query;
    let clauses = ['p.eliminado = FALSE'], values = [], idx = 1;

    if (canal && canal !== 'Todos') { clauses.push(`p.canal_venta = $${idx++}`); values.push(canal); }
    if (estado) { clauses.push(`p.estado = $${idx++}`); values.push(estado); }
    if (fechaInicio) { clauses.push(`(p.fecha_creacion AT TIME ZONE 'America/Hermosillo')::date >= $${idx++}`); values.push(fechaInicio); }
    if (fechaFin) { clauses.push(`(p.fecha_creacion AT TIME ZONE 'America/Hermosillo')::date <= $${idx++}`); values.push(fechaFin); }

    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    
    // AÑADIDO: Seleccionamos la columna 'recompensa'
    const query = `
        SELECT p.id, p.cliente, p.estado, CAST(p.total AS TEXT) AS total, CAST(p.comision AS TEXT) AS comision, p.fecha_creacion, p.canal_venta, p.metodo_pago, p.metodo_pago_secundario, CAST(p.monto_efectivo AS TEXT) AS monto_efectivo, CAST(p.monto_no_efectivo AS TEXT) AS monto_no_efectivo, CAST(p.propina AS TEXT) AS propina, p.tipo_consumo, CAST(p.descuento AS TEXT) AS descuento, p.recompensa, p.motivo_cancelacion, p.cancelado_por, p.fecha_cancelacion,
        json_agg(json_build_object(
            'menu_producto_id', pi.menu_producto_id,
            'nombre_producto', pi.nombre_producto, 
            'cantidad', pi.cantidad, 
            'precio_unitario', CAST(pi.precio_unitario AS TEXT),
            'notas', pi.notas 
        )) AS items 
        FROM pedidos p 
        JOIN pedido_items pi ON p.id = pi.pedido_id 
        ${where} 
        GROUP BY p.id ORDER BY p.fecha_creacion DESC`;

    try {
        const result = await pool.query(query, values);
        const pedidos = result.rows.map(p => ({
            ...p,
            total: parseFloat(p.total),
            comision: parseFloat(p.comision || 0),
            descuento: parseFloat(p.descuento || 0),
            propina: parseFloat(p.propina || 0),
            monto_efectivo: p.monto_efectivo !== null ? parseFloat(p.monto_efectivo) : null,
            monto_no_efectivo: p.monto_no_efectivo !== null ? parseFloat(p.monto_no_efectivo) : null,
            items: p.items.map(i => ({ ...i, precio_unitario: parseFloat(i.precio_unitario) }))
        }));
        res.status(200).json(pedidos);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/pedidos', async (req, res) => {
    const { cliente, telefono, items, canal_venta, total_ajustado, tipo_consumo, descuento, propina } = req.body;
    if (!cliente || !items.length) return res.status(400).json({ error: 'Datos incompletos' });

    let pago;
    try {
        pago = resolverPago(req.body, total_ajustado);
    } catch (err) {
        return res.status(400).json({ error: err.message });
    }
    const comision = pago.comision;
    const propinaFinal = parseFloat(propina) || 0;

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        let recompensa = false;

        // LÓGICA DE VISITAS Y RECOMPENSAS
        if (telefono) {
            const clienteRes = await client.query('SELECT id, visitas, ultima_visita FROM clientes WHERE telefono = $1', [telefono]);
            
            if (clienteRes.rows.length > 0) {
                const c = clienteRes.rows[0];
                
                // Verificar si la última visita fue HOY en Hermosillo
                const checkVisita = await client.query(`
                    SELECT (ultima_visita AT TIME ZONE 'America/Hermosillo')::date = (NOW() AT TIME ZONE 'America/Hermosillo')::date AS misma_fecha 
                    FROM clientes WHERE id = $1
                `, [c.id]);

                const mismaFecha = checkVisita.rows.length > 0 && checkVisita.rows[0].misma_fecha === true;

                if (!mismaFecha) {
                    // Es un día nuevo -> Sumamos 1 visita
                    const nuevasVisitas = c.visitas + 1;
                    if (nuevasVisitas % 8 === 0) recompensa = true; // Múltiplo de 8 = Cupón
                    
                    await client.query('UPDATE clientes SET visitas = $1, total_gastado = total_gastado + $2, ultima_visita = NOW(), nombre = $3 WHERE telefono = $4', [nuevasVisitas, total_ajustado, cliente, telefono]);
                } else {
                    // Es el mismo día -> Solo sumamos el dinero, NO la visita
                    await client.query('UPDATE clientes SET total_gastado = total_gastado + $1, nombre = $2 WHERE telefono = $3', [total_ajustado, cliente, telefono]);
                }
            } else {
                // Cliente Nuevo
                await client.query('INSERT INTO clientes (telefono, nombre, visitas, total_gastado, puntos, ultima_visita) VALUES ($1, $2, 1, $3, 1, NOW())', [telefono, cliente, total_ajustado]);
            }
        }

        // Guardar el Pedido (Ahora incluye si ganó recompensa)
        const pedRes = await client.query(
            `INSERT INTO pedidos (cliente, total, canal_venta, metodo_pago, metodo_pago_secundario, monto_efectivo, monto_no_efectivo, comision, tipo_consumo, descuento, recompensa, propina)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING id`,
            [cliente, total_ajustado, canal_venta || 'OyR', pago.metodo_pago, pago.metodo_pago_secundario, pago.monto_efectivo, pago.monto_no_efectivo, comision, tipo_consumo || 'Para Llevar', descuento || 0, recompensa, propinaFinal]
        );
        const pedidoId = pedRes.rows[0].id;

        for (const item of items) {
            await client.query(`INSERT INTO pedido_items (pedido_id, menu_producto_id, nombre_producto, cantidad, precio_unitario, notas) VALUES ($1, $2, $3, $4, $5, $6)`,
                [pedidoId, item.menu_producto_id, item.nombre_producto_completo, item.cantidad, item.precio_unitario, item.notas || '']);
        }

        await client.query('COMMIT');
        
        // Devolvemos la variable recompensa para que el POS sepa si debe lanzar alerta
        res.status(201).json({ id: pedidoId, mensaje: 'Pedido guardado', comision: comision.toFixed(2), recompensa });
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(500).json({ error: err.message });
    } finally { client.release(); }
});

app.put('/api/pedidos/:id', async (req, res) => {
    const { estado, items, cliente, total_ajustado, canal_venta, tipo_consumo, descuento, propina } = req.body;

    if (estado === 'Cancelado') {
        return res.status(400).json({ error: 'Usa PUT /api/pedidos/:id/cancelar para cancelar un pedido (requiere motivo).' });
    }

    let pago = null;
    if (items && items.length > 0) {
        try {
            pago = resolverPago(req.body, total_ajustado);
        } catch (err) {
            return res.status(400).json({ error: err.message });
        }
    }

    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        const actual = await client.query('SELECT estado, eliminado FROM pedidos WHERE id = $1', [req.params.id]);
        if (actual.rows.length === 0 || actual.rows[0].eliminado) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Pedido no encontrado.' });
        }
        if (actual.rows[0].estado === 'Entregado' || actual.rows[0].estado === 'Cancelado') {
            await client.query('ROLLBACK');
            return res.status(409).json({ error: `Este pedido ya está ${actual.rows[0].estado} y no se puede modificar.` });
        }

        if (items && items.length > 0) {
            const propinaFinal = parseFloat(propina) || 0;

            await client.query(
                `UPDATE pedidos SET cliente=$1, total=$2, canal_venta=$3, metodo_pago=$4, metodo_pago_secundario=$5, monto_efectivo=$6, monto_no_efectivo=$7, comision=$8, tipo_consumo=$9, descuento=$10, propina=$11 WHERE id=$12`,
                [cliente, total_ajustado, canal_venta, pago.metodo_pago, pago.metodo_pago_secundario, pago.monto_efectivo, pago.monto_no_efectivo, pago.comision, tipo_consumo, descuento, propinaFinal, req.params.id]
            );

            await client.query('DELETE FROM pedido_items WHERE pedido_id = $1', [req.params.id]);
            
            for (const item of items) {
                await client.query(`INSERT INTO pedido_items (pedido_id, menu_producto_id, nombre_producto, cantidad, precio_unitario, notas) VALUES ($1, $2, $3, $4, $5, $6)`,
                    [req.params.id, item.menu_producto_id, item.nombre_producto_completo, item.cantidad, item.precio_unitario, item.notas || '']);
            }
            await client.query('COMMIT');
            return res.status(200).json({ mensaje: 'Pedido actualizado' });
        }
        
        if (estado === 'Entregado') {
            const dbItems = await client.query('SELECT menu_producto_id, nombre_producto, cantidad FROM pedido_items WHERE pedido_id = $1', [req.params.id]);
            for (const item of dbItems.rows) {
                const prod = await client.query('SELECT receta_id FROM menu_productos WHERE id = $1', [item.menu_producto_id]);
                if (prod.rows[0]?.receta_id) {
                    const insumos = await client.query('SELECT insumo_id, cantidad_necesaria FROM receta_insumo WHERE receta_id = $1', [prod.rows[0].receta_id]);
                    for (const ins of insumos.rows) {
                        await client.query('UPDATE insumos SET cantidad = cantidad - $1 WHERE id = $2', [ins.cantidad_necesaria * item.cantidad, ins.insumo_id]);
                    }
                }
                const match = item.nombre_producto.match(/\((.*)\)/);
                if (match) {
                    const mods = match[1].split(',').map(m => m.trim());
                    for (const m of mods) {
                        const op = await client.query('SELECT insumo_id, cantidad_insumo FROM menu_opciones WHERE valor = $1 LIMIT 1', [m]);
                        if (op.rows.length && op.rows[0].insumo_id) {
                            await client.query('UPDATE insumos SET cantidad = cantidad - $1 WHERE id = $2', [op.rows[0].cantidad_insumo * item.cantidad, op.rows[0].insumo_id]);
                        }
                    }
                }
            }
        }
        await client.query('UPDATE pedidos SET estado = $1 WHERE id = $2', [estado, req.params.id]);
        await client.query('COMMIT');
        res.status(200).json({ mensaje: 'Estado actualizado' });
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(500).json({ error: err.message });
    } finally { client.release(); }
});

// Cancelar pedido (requiere motivo; queda registrado quién y cuándo)
app.put('/api/pedidos/:id/cancelar', async (req, res) => {
    const { motivo } = req.body;
    if (!motivo || !motivo.trim()) return res.status(400).json({ error: 'Se requiere un motivo para cancelar el pedido.' });

    try {
        const actual = await pool.query('SELECT estado, eliminado FROM pedidos WHERE id = $1', [req.params.id]);
        if (actual.rows.length === 0 || actual.rows[0].eliminado) return res.status(404).json({ error: 'Pedido no encontrado.' });
        if (actual.rows[0].estado === 'Entregado' || actual.rows[0].estado === 'Cancelado') {
            return res.status(409).json({ error: `Este pedido ya está ${actual.rows[0].estado} y no se puede cancelar.` });
        }

        await pool.query(
            'UPDATE pedidos SET estado = $1, motivo_cancelacion = $2, cancelado_por = $3, fecha_cancelacion = NOW() WHERE id = $4',
            ['Cancelado', motivo.trim(), req.user.username, req.params.id]
        );
        res.status(200).json({ mensaje: 'Pedido cancelado.' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Borrado lógico: el registro se conserva para trazabilidad contable, solo se oculta de listas y reportes.
app.delete('/api/pedidos/:id', async (req, res) => {
    try {
        const result = await pool.query(
            'UPDATE pedidos SET eliminado = TRUE, eliminado_por = $1, fecha_eliminacion = NOW() WHERE id = $2 AND eliminado = FALSE RETURNING id',
            [req.user.username, req.params.id]
        );
        if (result.rowCount === 0) return res.status(404).json({ error: 'Pedido no encontrado.' });
        res.status(204).send();
    } catch (err) { res.status(500).json({ error: err.message }); }
});


// ======================================================================
// 7. CLIENTES (CRM - BÚSQUEDA Y GESTIÓN)
// ======================================================================

// 7.1 Obtener todos los clientes o buscar por coincidencia
app.get('/api/clientes', async (req, res) => {
    const { buscar } = req.query;
    try {
        let query = 'SELECT id, nombre, telefono, visitas, total_gastado, puntos, ultima_visita FROM clientes';
        let params = [];
        
        // Si hay texto en el buscador, filtramos por nombre o teléfono
        if (buscar) {
            query += ' WHERE nombre ILIKE $1 OR telefono LIKE $1';
            params.push(`%${buscar}%`);
        }
        
        // Ordenamos para ver primero a los que visitaron más recientemente
        query += ' ORDER BY ultima_visita DESC NULLS LAST'; 
        
        const result = await pool.query(query, params);
        res.status(200).json(result.rows);
    } catch (err) { 
        res.status(500).json({ error: err.message }); 
    }
});

// 7.2 Búsqueda exacta por teléfono (Usado por el POS al cobrar)
app.get('/api/clientes/exacto/:telefono', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM clientes WHERE telefono = $1', [req.params.telefono]);
        if (result.rows.length) res.json(result.rows[0]);
        else res.status(404).json({ mensaje: 'Cliente no encontrado' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// 7.3 Actualizar el nombre del cliente
app.put('/api/clientes/:id', async (req, res) => {
    const { nombre } = req.body;
    try {
        const result = await pool.query('UPDATE clientes SET nombre = $1 WHERE id = $2 RETURNING *', [nombre, req.params.id]);
        if (result.rows.length) res.status(200).json(result.rows[0]);
        else res.status(404).json({ error: 'Cliente no encontrado' });
    } catch (err) { 
        res.status(500).json({ error: err.message }); 
    }
});
// ======================================================================
// 8. RECETAS (Endpoint Corregido)
// ======================================================================
app.get('/api/recetas', async (req, res) => {
    const query = `SELECT r.id, r.nombre, r.descripcion, r.pasos, 
        (SELECT json_agg(json_build_object('insumo_id', ri.insumo_id, 'cantidad_necesaria', CAST(ri.cantidad_necesaria AS TEXT), 'unidad_medida', ri.unidad_medida)) 
        FROM receta_insumo ri WHERE ri.receta_id = r.id) as ingredientes FROM Recetas r ORDER BY r.nombre`;
    try {
        const result = await pool.query(query);
        res.status(200).json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/recetas', async (req, res) => {
    const { nombre, descripcion, pasos, ingredientes, producto_venta_id } = req.body;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const resReceta = await client.query('INSERT INTO Recetas (nombre, descripcion, pasos) VALUES ($1, $2, $3) RETURNING id', [nombre, descripcion, pasos]);
        const id = resReceta.rows[0].id;
        for (const ing of ingredientes) {
            await client.query('INSERT INTO receta_insumo (receta_id, insumo_id, cantidad_necesaria, unidad_medida) VALUES ($1, $2, $3, $4)', 
                [id, ing.insumo_id, ing.cantidad_necesaria, ing.unidad_medida]);
        }
        if (producto_venta_id) await client.query('UPDATE menu_productos SET receta_id = $1 WHERE id = $2', [id, producto_venta_id]);
        await client.query('COMMIT');
        res.status(201).json({ mensaje: 'Receta creada' });
    } catch (err) { await client.query('ROLLBACK'); res.status(500).json({ error: err.message }); } finally { client.release(); }
});

// Endpoint PUT Recuperado
app.put('/api/recetas/:id', async (req, res) => {
    const id = parseInt(req.params.id, 10);
    const { nombre, descripcion, pasos, ingredientes, producto_venta_id } = req.body;
    const client = await pool.connect();

    if (!nombre || !ingredientes) return res.status(400).json({ error: 'Datos faltantes' });

    try {
        await client.query('BEGIN');
        await client.query('UPDATE recetas SET nombre = $1, descripcion = $2, pasos = $3 WHERE id = $4', [nombre, descripcion, pasos, id]);
        await client.query('DELETE FROM receta_insumo WHERE receta_id = $1', [id]);
        for (const ing of ingredientes) {
            await client.query('INSERT INTO receta_insumo (receta_id, insumo_id, cantidad_necesaria, unidad_medida) VALUES ($1, $2, $3, $4)', 
                [id, ing.insumo_id, ing.cantidad_necesaria, ing.unidad_medida]);
        }
        await client.query('UPDATE menu_productos SET receta_id = NULL WHERE receta_id = $1', [id]);
        if (producto_venta_id) await client.query('UPDATE menu_productos SET receta_id = $1 WHERE id = $2', [id, producto_venta_id]);
        await client.query('COMMIT');
        res.status(200).json({ mensaje: 'Receta actualizada' });
    } catch (err) { await client.query('ROLLBACK'); res.status(500).json({ error: err.message }); } finally { client.release(); }
});

app.delete('/api/recetas/:id', async (req, res) => {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        await client.query('UPDATE menu_productos SET receta_id = NULL WHERE receta_id = $1', [req.params.id]);
        await client.query('DELETE FROM receta_insumo WHERE receta_id = $1', [req.params.id]);
        await client.query('DELETE FROM recetas WHERE id = $1', [req.params.id]);
        await client.query('COMMIT');
        res.status(204).send();
    } catch (err) { await client.query('ROLLBACK'); res.status(500).json({ error: err.message }); } finally { client.release(); }
});


// ======================================================================
// 9. REPORTES (ESTADÍSTICAS)
// ======================================================================

// KPI
app.get('/api/reportes/cogs', async (req, res) => {
    const { fechaInicio, fechaFin } = req.query;
    try {
        const query = `
            SELECT SUM(usage.cantidad_total * i.costo_promedio) as costo_total_insumos
            FROM (
                SELECT insumo_id, SUM(cantidad_necesaria) as cantidad_total
                FROM receta_insumo ri
                JOIN pedido_items pi ON ri.receta_id = (SELECT receta_id FROM menu_productos WHERE id = pi.menu_producto_id)
                JOIN pedidos p ON pi.pedido_id = p.id
                WHERE p.estado = 'Entregado' AND p.eliminado = FALSE
                AND (p.fecha_creacion AT TIME ZONE 'America/Hermosillo')::date BETWEEN $1 AND $2
                GROUP BY insumo_id
            ) usage
            JOIN insumos i ON usage.insumo_id = i.id
        `;
        const result = await pool.query(query, [fechaInicio, fechaFin]);
        res.json({ costo_total: parseFloat(result.rows[0].costo_total_insumos || 0) });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// REPORTE SEMANAL GERENCIAL (Ventas + Compras Sugeridas)
app.get('/api/reportes/semanal', async (req, res) => {
    const { fechaInicio, fechaFin } = req.query;
    
    try {
        const client = await pool.connect();
        
        // 1. ANÁLISIS FINANCIERO (Desglose por Canal y Método de Pago)
        // Agrupa por canal (Uber/Didi/OyR) y método (Efectivo/Tarjeta)
        const ventasQuery = `
            SELECT 
                canal_venta,
                metodo_pago,
                COUNT(id) as pedidos,
                SUM(total) as venta_bruta,
                SUM(comision) as comisiones
            FROM Pedidos
            WHERE estado = 'Entregado' AND eliminado = FALSE
            AND (fecha_creacion AT TIME ZONE 'America/Hermosillo')::date >= $1
            AND (fecha_creacion AT TIME ZONE 'America/Hermosillo')::date <= $2
            GROUP BY canal_venta, metodo_pago
            ORDER BY canal_venta, metodo_pago
        `;
        const ventasRes = await client.query(ventasQuery, [fechaInicio, fechaFin]);

        // 2. STOCK Y LISTA DE COMPRAS (Agrupado por Proveedor)
        // Busca todo lo que esté bajo de stock o agotado
        const stockQuery = `
            SELECT 
                proveedor_preferido,
                nombre,
                cantidad,
                unidad,
                stock_minimo,
                (stock_minimo - cantidad) as faltante_sugerido,
                costo_promedio
            FROM Insumos
            WHERE cantidad <= stock_minimo
            ORDER BY proveedor_preferido, nombre
        `;
        const stockRes = await client.query(stockQuery);

        client.release();

        // 3. Procesamiento de Datos para el Frontend
        let financiero = {
            detalles: ventasRes.rows,
            total_bruto: 0,
            total_comisiones: 0,
            total_neto: 0,
            apps_detalle: {} // Para saber cuánto vendió cada app específicamente
        };

        ventasRes.rows.forEach(row => {
            const bruta = parseFloat(row.venta_bruta);
            const comision = parseFloat(row.comisiones);
            
            financiero.total_bruto += bruta;
            financiero.total_comisiones += comision;
            
            // Agrupar totales por App
            if (['Uber', 'Didi', 'Rappi'].includes(row.canal_venta)) {
                if (!financiero.apps_detalle[row.canal_venta]) financiero.apps_detalle[row.canal_venta] = 0;
                financiero.apps_detalle[row.canal_venta] += bruta;
            }
        });
        
        financiero.total_neto = financiero.total_bruto - financiero.total_comisiones;

        // Agrupar Compras por Proveedor
        let compras_sugeridas = {};
        let costo_estimado_resurtido = 0;

        stockRes.rows.forEach(item => {
            const prov = item.proveedor_preferido || 'Sin Asignar';
            if (!compras_sugeridas[prov]) compras_sugeridas[prov] = [];
            
            // Calculamos cuánto costaría rellenar el stock al mínimo
            const costoEstimado = item.faltante_sugerido * parseFloat(item.costo_promedio || 0);
            if (costoEstimado > 0) costo_estimado_resurtido += costoEstimado;

            compras_sugeridas[prov].push({
                nombre: item.nombre,
                stock_actual: parseFloat(item.cantidad),
                minimo: item.stock_minimo,
                pedir: parseFloat(item.faltante_sugerido).toFixed(2) + ' ' + item.unidad,
                estado: item.cantidad <= 0 ? 'AGOTADO 🔴' : 'BAJO ⚠️'
            });
        });

        res.json({
            financiero,
            compras: compras_sugeridas,
            costo_estimado_resurtido: costo_estimado_resurtido.toFixed(2)
        });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Ventas (Con Zona Horaria Correcta y Comisiones)
app.get('/api/reportes/ventas', async (req, res) => {
    const { fechaInicio, fechaFin } = req.query;
    try {
        // Agregamos SUM(comision)
        const query = `SELECT COUNT(id) AS total_pedidos, SUM(total) AS ventas_totales, SUM(comision) AS comisiones_totales 
            FROM Pedidos
            WHERE (fecha_creacion AT TIME ZONE 'America/Hermosillo')::date >= $1
            AND (fecha_creacion AT TIME ZONE 'America/Hermosillo')::date <= $2
            AND estado = 'Entregado' AND eliminado = FALSE`;
        const result = await pool.query(query, [fechaInicio, fechaFin]);
        res.status(200).json({
            fechaInicio, fechaFin, 
            total_pedidos: parseInt(result.rows[0].total_pedidos || 0), 
            ventas_totales: parseFloat(result.rows[0].ventas_totales || 0).toFixed(2),
            comisiones: parseFloat(result.rows[0].comisiones_totales || 0).toFixed(2)
        });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Ventas del Turno Actual (Desde el último corte de caja)
app.get('/api/reportes/ventas-turno', async (req, res) => {
    try {
        // 1. Buscar la fecha y hora exacta del último corte
        const ultimoCorteQuery = await pool.query('SELECT MAX(fecha_corte) as ultimo FROM cortes_caja');
        const ultimoCorte = ultimoCorteQuery.rows[0].ultimo;

        let query;
        let params = [];

        if (ultimoCorte) {
            // Si hay un corte previo, sumamos todo a partir de ese segundo exacto
            query = `SELECT COUNT(id) AS total_pedidos, SUM(total) AS ventas_totales, SUM(comision) AS comisiones_totales
                     FROM Pedidos
                     WHERE fecha_creacion > $1 AND estado = 'Entregado' AND eliminado = FALSE`;
            params.push(ultimoCorte);
        } else {
            // Si por alguna razón es la primera vez que se usa el sistema y no hay cortes
            query = `SELECT COUNT(id) AS total_pedidos, SUM(total) AS ventas_totales, SUM(comision) AS comisiones_totales
                     FROM Pedidos
                     WHERE (fecha_creacion AT TIME ZONE 'America/Hermosillo')::date = (NOW() AT TIME ZONE 'America/Hermosillo')::date
                     AND estado = 'Entregado' AND eliminado = FALSE`;
        }

        const result = await pool.query(query, params);
        res.status(200).json({
            total_pedidos: parseInt(result.rows[0].total_pedidos || 0), 
            ventas_totales: parseFloat(result.rows[0].ventas_totales || 0).toFixed(2),
            comisiones: parseFloat(result.rows[0].comisiones_totales || 0).toFixed(2)
        });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Platillos Más Vendidos
app.get('/api/reportes/platillos', async (req, res) => {
    const { fechaInicio, fechaFin } = req.query;
    try {
        const query = `SELECT mp.nombre_venta AS producto, SUM(pi.cantidad) AS cantidad_vendida, SUM(pi.cantidad * pi.precio_unitario) AS ingreso_generado
            FROM pedido_items pi JOIN pedidos p ON pi.pedido_id = p.id JOIN menu_productos mp ON pi.menu_producto_id = mp.id
            WHERE p.estado = 'Entregado' AND p.eliminado = FALSE AND (p.fecha_creacion AT TIME ZONE 'America/Hermosillo')::date >= $1 AND (p.fecha_creacion AT TIME ZONE 'America/Hermosillo')::date <= $2
            GROUP BY mp.nombre_venta ORDER BY cantidad_vendida DESC`;
        const result = await pool.query(query, [fechaInicio, fechaFin]);
        res.status(200).json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Reporte Histórico de Inventario (Recuperado)
app.get('/api/reportes/inventario', async (req, res) => {
    const { fecha } = req.query;
    if (!fecha) return res.status(400).json({ error: 'Falta fecha' });
    try {
        const query = `SELECT fecha_registro, nombre_insumo, cantidad_registrada, unidad_medida, categoria 
            FROM Registro_Inventario WHERE fecha_registro::date = $1 ORDER BY nombre_insumo`;
        const result = await pool.query(query, [fecha]);
        res.status(200).json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Insumos Teóricos
app.get('/api/reportes/insumos-teoricos', async (req, res) => {
    const { fechaInicio, fechaFin } = req.query;
    try {
        const client = await pool.connect();
        
        // 1. Obtener Ventas
        const ventas = await client.query(`
            SELECT pi.menu_producto_id, pi.nombre_producto, pi.cantidad 
            FROM pedido_items pi JOIN pedidos p ON pi.pedido_id = p.id
            WHERE p.estado = 'Entregado' AND p.eliminado = FALSE
            AND (p.fecha_creacion AT TIME ZONE 'America/Hermosillo')::date >= $1
            AND (p.fecha_creacion AT TIME ZONE 'America/Hermosillo')::date <= $2`, [fechaInicio, fechaFin]);

        // 2. Obtener Recetas
        const recetas = await client.query(`
            SELECT mp.id as producto_id, i.nombre as nombre_insumo, ri.cantidad_necesaria, ri.unidad_medida
            FROM menu_productos mp 
            JOIN recetas r ON mp.receta_id = r.id
            JOIN receta_insumo ri ON r.id = ri.receta_id
            JOIN insumos i ON ri.insumo_id = i.id`);
        
        // 3. Obtener Opciones
        const opciones = await client.query(`
            SELECT mo.valor, i.nombre as nombre_insumo, mo.cantidad_insumo, mo.unidad_insumo
            FROM menu_opciones mo JOIN insumos i ON mo.insumo_id = i.id WHERE mo.insumo_id IS NOT NULL`);

        // Mapear para acceso rápido
        const mapRecetas = {};
        recetas.rows.forEach(r => {
            if(!mapRecetas[r.producto_id]) mapRecetas[r.producto_id] = [];
            mapRecetas[r.producto_id].push(r);
        });
        
        const mapOpciones = {};
        opciones.rows.forEach(o => mapOpciones[o.valor.toUpperCase()] = o);

        // Calcular
        const uso = {};
        ventas.rows.forEach(v => {
            // Receta Base
            if(mapRecetas[v.menu_producto_id]) {
                mapRecetas[v.menu_producto_id].forEach(ing => {
                    if(!uso[ing.nombre_insumo]) uso[ing.nombre_insumo] = { cant: 0, unidad: ing.unidad_medida };
                    uso[ing.nombre_insumo].cant += (ing.cantidad_necesaria * v.cantidad);
                });
            }
            // Modificadores
            const match = v.nombre_producto.match(/\((.*)\)/);
            if(match) {
                const mods = match[1].split(',').map(m => m.trim().toUpperCase());
                mods.forEach(m => {
                    if(mapOpciones[m]) {
                        const ing = mapOpciones[m];
                        if(!uso[ing.nombre_insumo]) uso[ing.nombre_insumo] = { cant: 0, unidad: ing.unidad_insumo };
                        uso[ing.nombre_insumo].cant += (ing.cantidad_insumo * v.cantidad);
                    }
                });
            }
        });

        client.release();
        const reporte = Object.keys(uso).map(k => ({ nombre_insumo: k, cantidad_total: uso[k].cant, unidad: uso[k].unidad })).sort((a,b) => b.cantidad_total - a.cantidad_total);
        res.status(200).json(reporte);

    } catch (err) { res.status(500).json({ error: err.message }); }
});


// ======================================================================
// 10. DEBUGGING
// ======================================================================
app.get('/api/debug/hora', async (req, res) => {
    try {
        const result = await pool.query(`SELECT NOW() as utc, (NOW() AT TIME ZONE 'America/Hermosillo') as hermosillo`);
        res.json(result.rows[0]);
    } catch (err) { res.json({ error: err.message }); }
});

// ======================================================================
// MÓDULO DE CORTE DE CAJA (ARQUEO)
// ======================================================================

// Calcula las ventas 'Entregado' agrupadas por método de pago desde el último corte
// (o desde siempre, si nunca se ha hecho uno). La usan tanto la previsualización como el
// guardado real, para que el corte SIEMPRE se calcule con datos frescos de la BD y nunca
// con lo que mande el cliente.
async function calcularVentasDesdeUltimoCorte(client) {
    const ultimoCorteQuery = await client.query('SELECT MAX(fecha_corte) as ultimo FROM cortes_caja');
    const ultimoCorte = ultimoCorteQuery.rows[0].ultimo;

    const filtroFecha = ultimoCorte ? 'AND fecha_creacion > $1' : '';
    const params = ultimoCorte ? [ultimoCorte] : [];

    // Un pedido 'Mixto' aporta a DOS bolsillos: su parte en efectivo, y su parte en el método
    // secundario. Lo "des-pivoteamos" en dos filas (UNION ALL) para que cada bolsillo sume
    // exactamente lo que físicamente debe haber de ese método, no el total completo del pedido.
    const query = `
        SELECT bucket, SUM(monto) as total FROM (
            SELECT CASE WHEN metodo_pago = 'Mixto' THEN 'Efectivo' ELSE metodo_pago END AS bucket,
                   CASE WHEN metodo_pago = 'Mixto' THEN monto_efectivo ELSE total END AS monto
            FROM Pedidos WHERE estado = 'Entregado' AND eliminado = FALSE ${filtroFecha}
            UNION ALL
            SELECT metodo_pago_secundario AS bucket, monto_no_efectivo AS monto
            FROM Pedidos WHERE estado = 'Entregado' AND eliminado = FALSE AND metodo_pago = 'Mixto' ${filtroFecha}
        ) x GROUP BY bucket
    `;
    const result = await client.query(query, params);

    const resumen = { Efectivo: 0, Tarjeta: 0, Transferencia: 0, 'Aplicación': 0 };
    result.rows.forEach(row => {
        const metodo = row.bucket || 'Efectivo';
        const total = parseFloat(row.total);
        if (metodo.includes('Aplicación')) resumen['Aplicación'] += total;
        else if (metodo.includes('Tarjeta')) resumen['Tarjeta'] += total;
        else if (metodo.includes('Transferencia')) resumen['Transferencia'] += total;
        else resumen['Efectivo'] += total;
    });

    // Propinas del periodo: informativas, no forman parte de la reconciliación de caja.
    const propinasQuery = await client.query(
        `SELECT COALESCE(SUM(propina), 0) as total FROM Pedidos WHERE estado = 'Entregado' AND eliminado = FALSE ${filtroFecha}`,
        params
    );
    resumen.propinas = parseFloat(propinasQuery.rows[0].total || 0);

    return resumen;
}

// 1. Obtener Pre-Visualización del Corte (Calcula totales del día actual)
// [GET] /api/corte/preview - CORTE POR TURNO (Lógica: Ventas desde el último cierre)
app.get('/api/corte/preview', async (req, res) => {
    try {
        const resumen = await calcularVentasDesdeUltimoCorte(pool);
        res.json(resumen);
    } catch (err) {
        console.error('Error en previsualización de corte:', err);
        res.status(500).json({ error: err.message });
    }
});

// 2. Historial de cortes realizados
app.get('/api/corte/historial', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT id, fecha_corte, usuario,
                CAST(total_ventas AS TEXT) AS total_ventas,
                CAST(esperado_efectivo AS TEXT) AS esperado_efectivo,
                CAST(esperado_tarjeta AS TEXT) AS esperado_tarjeta,
                CAST(esperado_transferencia AS TEXT) AS esperado_transferencia,
                CAST(esperado_apps AS TEXT) AS esperado_apps,
                CAST(real_efectivo AS TEXT) AS real_efectivo,
                CAST(real_tarjeta AS TEXT) AS real_tarjeta,
                CAST(diferencia AS TEXT) AS diferencia,
                CAST(propinas_periodo AS TEXT) AS propinas_periodo,
                observaciones
            FROM cortes_caja ORDER BY fecha_corte DESC LIMIT 50
        `);
        res.status(200).json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// 3. Guardar el Corte Definitivo. Recalcula lo esperado del lado del servidor (nunca confía
// en lo que mande el cliente) y rechaza el corte si no hay ventas nuevas desde el último —
// esto es lo que evita un doble corte accidental (doble clic, o reenvío de un formulario viejo).
app.post('/api/corte', async (req, res) => {
    const { totales_reales, observaciones } = req.body;
    if (!totales_reales) return res.status(400).json({ error: "Datos incompletos" });

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const esperado = await calcularVentasDesdeUltimoCorte(client);
        const total_ventas = esperado.Efectivo + esperado.Tarjeta + esperado.Transferencia + esperado['Aplicación'];

        if (total_ventas <= 0) {
            await client.query('ROLLBACK');
            return res.status(409).json({ error: 'No hay ventas nuevas desde el último corte. Es posible que ya se haya cerrado la caja.' });
        }

        const real_efectivo = parseFloat(totales_reales.efectivo || 0);
        const real_tarjeta = parseFloat(totales_reales.tarjeta || 0);
        const diferencia = real_efectivo - esperado.Efectivo;

        const result = await client.query(
            `INSERT INTO cortes_caja
             (usuario, total_ventas, esperado_efectivo, esperado_tarjeta, esperado_transferencia, esperado_apps, real_efectivo, real_tarjeta, diferencia, propinas_periodo, observaciones)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
             RETURNING id, fecha_corte`,
            [req.user.username, total_ventas, esperado.Efectivo, esperado.Tarjeta, esperado.Transferencia, esperado['Aplicación'], real_efectivo, real_tarjeta, diferencia, esperado.propinas, observaciones || '']
        );

        await client.query('COMMIT');
        res.status(201).json({ mensaje: 'Corte guardado correctamente', id: result.rows[0].id });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error("ERROR EN CORTE:", err);
        res.status(500).json({ error: err.message });
    } finally { client.release(); }
});

// ======================================================================
// 11. ALERTAS A COCINA (INTERCOMUNICADOR)
// ======================================================================

// Obtener alertas pendientes
app.get('/api/alertas', async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM alertas_cocina WHERE estado = 'Pendiente' ORDER BY fecha_creacion ASC");
        res.status(200).json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Crear nueva alerta desde caja
app.post('/api/alertas', async (req, res) => {
    const { mensaje } = req.body;
    try {
        const result = await pool.query('INSERT INTO alertas_cocina (mensaje) VALUES ($1) RETURNING *', [mensaje]);
        res.status(201).json(result.rows[0]);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Marcar alerta como completada desde cocina
app.put('/api/alertas/:id', async (req, res) => {
    try {
        await pool.query("UPDATE alertas_cocina SET estado = 'Completada' WHERE id = $1", [req.params.id]);
        res.status(200).json({ mensaje: 'Alerta completada' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ======================================================================
// 12. PRODUCCIÓN INTERNA (SUB-RECETAS)
// ======================================================================

// 1. Obtener todas las recetas de producción
app.get('/api/produccion/recetas', async (req, res) => {
    try {
        const query = `
            SELECT rp.id, rp.nombre, rp.insumo_resultado_id, i.nombre as nombre_resultado, rp.cantidad_resultado, i.unidad as unidad_resultado,
            (SELECT json_agg(json_build_object('insumo_origen_id', pd.insumo_origen_id, 'nombre', io.nombre, 'cantidad_necesaria', CAST(pd.cantidad_necesaria AS TEXT), 'unidad', io.unidad))
             FROM produccion_detalles pd JOIN insumos io ON pd.insumo_origen_id = io.id WHERE pd.receta_produccion_id = rp.id) as ingredientes
            FROM recetas_produccion rp
            JOIN insumos i ON rp.insumo_resultado_id = i.id
            ORDER BY rp.nombre`;
        const result = await pool.query(query);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// 2. Crear una nueva receta de producción (Ej. "Tanda de Ranch")
app.post('/api/produccion/recetas', async (req, res) => {
    const { nombre, insumo_resultado_id, cantidad_resultado, ingredientes } = req.body;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const resReceta = await client.query(
            'INSERT INTO recetas_produccion (nombre, insumo_resultado_id, cantidad_resultado) VALUES ($1, $2, $3) RETURNING id',
            [nombre, insumo_resultado_id, cantidad_resultado]
        );
        const recetaId = resReceta.rows[0].id;
        
        for (const ing of ingredientes) {
            await client.query(
                'INSERT INTO produccion_detalles (receta_produccion_id, insumo_origen_id, cantidad_necesaria) VALUES ($1, $2, $3)',
                [recetaId, ing.insumo_id, ing.cantidad]
            );
        }
        await client.query('COMMIT');
        res.status(201).json({ mensaje: 'Receta de producción creada' });
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(500).json({ error: err.message });
    } finally { client.release(); }
});

// 3. Eliminar receta de producción
app.delete('/api/produccion/recetas/:id', async (req, res) => {
    try {
        await pool.query('DELETE FROM recetas_produccion WHERE id = $1', [req.params.id]);
        res.status(204).send();
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// 4. EJECUTAR PRODUCCIÓN (Resta insumos crudos, Suma producto final)
app.post('/api/produccion/ejecutar', async (req, res) => {
    const { receta_produccion_id, tandas } = req.body;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        // A. Obtener receta y su resultado
        const recetaRes = await client.query('SELECT insumo_resultado_id, cantidad_resultado FROM recetas_produccion WHERE id = $1', [receta_produccion_id]);
        if (recetaRes.rows.length === 0) throw new Error("Receta no encontrada");
        const receta = recetaRes.rows[0];

        // B. Obtener ingredientes crudos requeridos
        const ingredientesRes = await client.query('SELECT insumo_origen_id, cantidad_necesaria FROM produccion_detalles WHERE receta_produccion_id = $1', [receta_produccion_id]);
        
        // C. Descontar materia prima multiplicada por las "tandas"
        for (const ing of ingredientesRes.rows) {
            const aDescontar = parseFloat(ing.cantidad_necesaria) * parseFloat(tandas);
            await client.query('UPDATE insumos SET cantidad = cantidad - $1 WHERE id = $2', [aDescontar, ing.insumo_origen_id]);
        }

        // D. Sumar el producto preparado al inventario
        const aSumar = parseFloat(receta.cantidad_resultado) * parseFloat(tandas);
        await client.query('UPDATE insumos SET cantidad = cantidad + $1 WHERE id = $2', [aSumar, receta.insumo_resultado_id]);

        await client.query('COMMIT');
        res.status(200).json({ mensaje: 'Producción registrada. Inventario actualizado exitosamente.' });
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(500).json({ error: err.message });
    } finally { client.release(); }
});

// ======================================================================
// INICIO DEL SERVIDOR
// ======================================================================
app.listen(PORT, () => {
    console.log(`🚀 Servidor Olimpollo Pro corriendo en el puerto ${PORT}`);
});
