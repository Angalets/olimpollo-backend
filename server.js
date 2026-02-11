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
app.get('/api/usuarios', async (req, res) => {
    try {
        const result = await pool.query('SELECT id, username, rol FROM Usuarios ORDER BY id');
        res.status(200).json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Crear Usuario
app.post('/api/usuarios', async (req, res) => {
    const { username, password, rol } = req.body;
    try {
        const existing = await pool.query('SELECT id FROM Usuarios WHERE username = $1', [username]);
        if (existing.rows.length > 0) return res.status(400).json({ error: 'El usuario ya existe.' });

        const hash = await bcrypt.hash(password, 10);
        const result = await pool.query('INSERT INTO Usuarios (username, password_hash, rol) VALUES ($1, $2, $3) RETURNING id, username, rol', [username, hash, rol]);
        res.status(201).json(result.rows[0]); 
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Eliminar Usuario
app.delete('/api/usuarios/:id', async (req, res) => {
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
        const prodRes = await pool.query('SELECT id, nombre_venta, categoria, CAST(precio_base AS TEXT) AS precio_base, grupos_modificadores FROM menu_productos ORDER BY categoria, nombre_venta');
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
        const result = await pool.query('SELECT id, nombre_venta, categoria, receta_id FROM menu_productos ORDER BY nombre_venta');
        res.status(200).json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/menu/productos', async (req, res) => {
    const { nombre_venta, precio_base, categoria, receta_id, descripcion, grupos_modificadores } = req.body;
    try {
        const result = await pool.query(`INSERT INTO menu_productos (nombre_venta, precio_base, categoria, receta_id, descripcion, grupos_modificadores) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`, 
            [nombre_venta, parseFloat(precio_base), categoria, receta_id || null, descripcion, grupos_modificadores || '']);
        res.status(201).json(result.rows[0]);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/menu/productos/:id', async (req, res) => {
    const { nombre_venta, precio_base, categoria, receta_id, descripcion, grupos_modificadores } = req.body;
    try {
        const result = await pool.query(`UPDATE menu_productos SET nombre_venta=$1, precio_base=$2, categoria=$3, receta_id=$4, descripcion=$5, grupos_modificadores=$6 WHERE id=$7 RETURNING *`, 
            [nombre_venta, parseFloat(precio_base), categoria, receta_id || null, descripcion, grupos_modificadores || '', req.params.id]);
        if (result.rowCount === 0) return res.status(404).json({ error: 'No encontrado' });
        res.status(200).json(result.rows[0]);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/menu/productos/:id', async (req, res) => {
    try {
        await pool.query('DELETE FROM menu_productos WHERE id = $1', [req.params.id]);
        res.status(204).send();
    } catch (err) { res.status(500).json({ error: err.message }); }
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
        const result = await pool.query('INSERT INTO menu_opciones (nombre_opcion, valor, precio_adicional) VALUES ($1, $2, $3) RETURNING *', 
            [req.body.nombre_opcion, req.body.valor, parseFloat(req.body.precio_adicional) || 0]);
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
// 5. INVENTARIO Y COMPRAS
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
    const query = `
        SELECT id, nombre, cantidad, unidad, stock_minimo, categoria, 
        CASE WHEN cantidad <= 0 THEN 'Agotado' WHEN cantidad <= stock_minimo THEN 'Requiere re-stock' ELSE 'En stock' END AS estado
        FROM Insumos ${where} ORDER BY id;`;

    try {
        const result = await pool.query(query, values);
        res.status(200).json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Crear Insumo
app.post('/api/inventario', async (req, res) => {
    const { nombre, cantidad, unidad, stock_minimo, categoria } = req.body;
    try {
        const result = await pool.query('INSERT INTO Insumos (nombre, cantidad, unidad, stock_minimo, categoria) VALUES ($1, $2, $3, $4, $5) RETURNING *', 
            [nombre, parseInt(cantidad), unidad, parseInt(stock_minimo), categoria]);
        res.status(201).json(result.rows[0]);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Editar Insumo
app.put('/api/inventario/:id', async (req, res) => {
    const { nombre, cantidad, unidad, stock_minimo, categoria } = req.body;
    try {
        const result = await pool.query('UPDATE Insumos SET nombre=$1, cantidad=$2, unidad=$3, stock_minimo=$4, categoria=$5 WHERE id=$6 RETURNING *',
            [nombre, parseInt(cantidad), unidad, parseInt(stock_minimo), categoria, req.params.id]);
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
                // Evitar división por cero
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

// GET: Lista de Pedidos con Filtros
app.get('/api/pedidos', async (req, res) => {
    // Limpieza automática de estados viejos
    await pool.query(`UPDATE pedidos SET estado = 'Entregado' WHERE estado = 'Pendiente' AND fecha_creacion < NOW() - INTERVAL '1 hour'`);

    const { canal, estado, fechaInicio, fechaFin } = req.query;
    let clauses = [], values = [], idx = 1;

    if (canal && canal !== 'Todos') { clauses.push(`p.canal_venta = $${idx++}`); values.push(canal); }
    if (estado) { clauses.push(`p.estado = $${idx++}`); values.push(estado); }
    // Filtros de fecha con Zona Horaria Hermosillo
    if (fechaInicio) { clauses.push(`(p.fecha_creacion AT TIME ZONE 'America/Hermosillo')::date >= $${idx++}`); values.push(fechaInicio); }
    if (fechaFin) { clauses.push(`(p.fecha_creacion AT TIME ZONE 'America/Hermosillo')::date <= $${idx++}`); values.push(fechaFin); }

    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    
    // Consulta Actualizada: Trae comision y metodo_pago
    const query = `
        SELECT p.id, p.cliente, p.estado, CAST(p.total AS TEXT) AS total, CAST(p.comision AS TEXT) AS comision, p.fecha_creacion, p.canal_venta, p.metodo_pago,
        json_agg(json_build_object(
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
            comision: parseFloat(p.comision || 0), // Parseamos la comisión
            items: p.items.map(i => ({ ...i, precio_unitario: parseFloat(i.precio_unitario) })) 
        }));
        res.status(200).json(pedidos);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// [POST] /api/pedidos - Crear Pedido (Con CRM, Notas y Comisiones de Tarjeta/Apps)
app.post('/api/pedidos', async (req, res) => {
    const { cliente, telefono, items, canal_venta, total_ajustado, metodo_pago } = req.body;
    if (!cliente || !items.length) return res.status(400).json({ error: 'Datos incompletos' });

    const totalCalculado = items.reduce((sum, i) => sum + (i.cantidad * i.precio_unitario), 0);
    const totalFinal = total_ajustado ?? totalCalculado;
    
    // --- LÓGICA DE COMISIÓN ACTUALIZADA ---
    let comision = 0;

    if (metodo_pago === 'Tarjeta') {
        // Tarjeta: 3.6% + IVA (16%) = 4.176%
        comision = totalFinal * 0.04176;
    } else if (metodo_pago === 'Aplicación') {
        // Apps (Uber/Didi/Rappi): 42.13% (Promedio configurado)
        comision = totalFinal * 0.4213;
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 1. CRM: Gestión de Cliente
        if (telefono) {
            const existe = await client.query('SELECT id FROM clientes WHERE telefono = $1', [telefono]);
            if (existe.rows.length > 0) {
                await client.query('UPDATE clientes SET visitas = visitas + 1, total_gastado = total_gastado + $1, ultima_visita = NOW(), nombre = $2 WHERE telefono = $3', [totalFinal, cliente, telefono]);
            } else {
                await client.query('INSERT INTO clientes (telefono, nombre, visitas, total_gastado, puntos) VALUES ($1, $2, 1, $3, 1)', [telefono, cliente, totalFinal]);
            }
        }

        // 2. Insertar Pedido (Incluyendo la comisión calculada)
        const pedRes = await client.query('INSERT INTO pedidos (cliente, total, canal_venta, metodo_pago, comision) VALUES ($1, $2, $3, $4, $5) RETURNING id', 
            [cliente, totalFinal, canal_venta || 'OyR', metodo_pago || 'Efectivo', comision]);
        const pedidoId = pedRes.rows[0].id;

        // 3. Insertar Items con Notas
        for (const item of items) {
            await client.query(`INSERT INTO pedido_items (pedido_id, menu_producto_id, nombre_producto, cantidad, precio_unitario, notas) VALUES ($1, $2, $3, $4, $5, $6)`,
                [pedidoId, item.menu_producto_id, item.nombre_producto_completo, item.cantidad, item.precio_unitario, item.notas || '']);
        }

        await client.query('COMMIT');
        res.status(201).json({ id: pedidoId, mensaje: 'Pedido guardado', comision: comision.toFixed(2) });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error(err);
        res.status(500).json({ error: err.message });
    } finally { client.release(); }
});

// PUT: Cambiar Estado y Descontar Inventario
app.put('/api/pedidos/:id', async (req, res) => {
    const { estado } = req.body;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        // Si el pedido se entrega, descontamos inventario
        if (estado === 'Entregado') {
            const items = await client.query('SELECT menu_producto_id, nombre_producto, cantidad FROM pedido_items WHERE pedido_id = $1', [req.params.id]);
            
            for (const item of items.rows) {
                // A. Descuento Receta Base
                const prod = await client.query('SELECT receta_id FROM menu_productos WHERE id = $1', [item.menu_producto_id]);
                if (prod.rows[0]?.receta_id) {
                    const insumos = await client.query('SELECT insumo_id, cantidad_necesaria FROM receta_insumo WHERE receta_id = $1', [prod.rows[0].receta_id]);
                    for (const ins of insumos.rows) {
                        await client.query('UPDATE insumos SET cantidad = cantidad - $1 WHERE id = $2', [ins.cantidad_necesaria * item.cantidad, ins.insumo_id]);
                    }
                }
                // B. Descuento Modificadores (Strings entre paréntesis)
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

// DELETE: Eliminar Pedido
app.delete('/api/pedidos/:id', async (req, res) => {
    try {
        await pool.query('DELETE FROM Pedidos WHERE id = $1', [req.params.id]);
        res.status(204).send();
    } catch (err) { res.status(500).json({ error: err.message }); }
});


// ======================================================================
// 7. CLIENTES (CRM - BÚSQUEDA)
// ======================================================================
app.get('/api/clientes/:telefono', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM clientes WHERE telefono = $1', [req.params.telefono]);
        if (result.rows.length) res.json(result.rows[0]);
        else res.status(404).json({ mensaje: 'Cliente no encontrado' });
    } catch (err) { res.status(500).json({ error: err.message }); }
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
            WHERE estado = 'Entregado'
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
            AND estado = 'Entregado'`;
        const result = await pool.query(query, [fechaInicio, fechaFin]);
        res.status(200).json({
            fechaInicio, fechaFin, 
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
            WHERE p.estado = 'Entregado' AND (p.fecha_creacion AT TIME ZONE 'America/Hermosillo')::date >= $1 AND (p.fecha_creacion AT TIME ZONE 'America/Hermosillo')::date <= $2
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
            WHERE p.estado = 'Entregado' 
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

// 1. Obtener Pre-Visualización del Corte (Calcula totales del día actual)
// [GET] /api/corte/preview - CORTE POR TURNO (Lógica: Ventas desde el último cierre)
app.get('/api/corte/preview', async (req, res) => {
    try {
        // 1. Buscamos la fecha y hora EXACTA del último corte realizado en la historia
        const ultimoCorteQuery = await pool.query('SELECT MAX(fecha_corte) as ultimo FROM cortes_caja');
        const ultimoCorte = ultimoCorteQuery.rows[0].ultimo;

        let query;
        let params = [];

        // 2. Construimos la consulta dependiendo si hay historia o es el primer día
        if (ultimoCorte) {
            // CASO NORMAL: Traemos ventas registradas DESPUÉS del último corte
            // Esto cubre turnos de madrugada (ej: 5pm a 1am) y días inactivos (Domingo a Jueves)
            query = `
                SELECT metodo_pago, SUM(total) as total 
                FROM Pedidos 
                WHERE estado = 'Entregado' 
                AND fecha_creacion > $1
                GROUP BY metodo_pago
            `;
            params.push(ultimoCorte);
        } else {
            // CASO INICIAL: Si nunca se ha hecho un corte, traemos TODO lo histórico
            query = `
                SELECT metodo_pago, SUM(total) as total 
                FROM Pedidos 
                WHERE estado = 'Entregado'
                GROUP BY metodo_pago
            `;
        }
        
        const result = await pool.query(query, params);
        
        // 3. Formateamos la respuesta para el Frontend (Ceros por defecto)
        const resumen = {
            Efectivo: 0,
            Tarjeta: 0,
            Transferencia: 0,
            Aplicación: 0
        };

        result.rows.forEach(row => {
            // Normalizamos el nombre del método de pago para evitar errores por mayúsculas/tildes
            const metodo = row.metodo_pago || 'Efectivo';
            const total = parseFloat(row.total);

            if (metodo.includes('Aplicación')) resumen['Aplicación'] += total;
            else if (metodo.includes('Tarjeta')) resumen['Tarjeta'] += total;
            else if (metodo.includes('Transferencia')) resumen['Transferencia'] += total;
            else resumen['Efectivo'] += total;
        });

        res.json(resumen);

    } catch (err) {
        console.error('Error en previsualización de corte:', err);
        res.status(500).json({ error: err.message });
    }
});

// 2. Guardar el Corte Definitivo (ESTE ES EL BLOQUE QUE TE FALTA)
app.post('/api/corte', async (req, res) => {
    try {
        console.log("Recibiendo petición de corte:", req.body); 

        const { usuario, totales_esperados, totales_reales, observaciones } = req.body;
        
        // Validación básica
        if (!totales_esperados || !totales_reales) {
            return res.status(400).json({ error: "Datos incompletos" });
        }

        // Cálculos seguros
        const total_ventas = Object.values(totales_esperados).reduce((a, b) => a + parseFloat(b || 0), 0);
        
        const real_efectivo = parseFloat(totales_reales.efectivo || 0);
        const real_tarjeta = parseFloat(totales_reales.tarjeta || 0);
        
        const esperado_efectivo = parseFloat(totales_esperados.Efectivo || 0);
        const esperado_tarjeta = parseFloat(totales_esperados.Tarjeta || 0);
        
        const diferencia = real_efectivo - esperado_efectivo; 

        // Guardar en BD
        const query = `
            INSERT INTO cortes_caja 
            (usuario, total_ventas, esperado_efectivo, esperado_tarjeta, esperado_transferencia, esperado_apps, real_efectivo, real_tarjeta, diferencia, observaciones)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING id, fecha_corte
        `;
        const values = [
            usuario || 'Anonimo', 
            total_ventas,
            esperado_efectivo, 
            esperado_tarjeta, 
            parseFloat(totales_esperados.Transferencia || 0), 
            parseFloat(totales_esperados['Aplicación'] || 0),
            real_efectivo, 
            real_tarjeta,
            diferencia, 
            observaciones || ''
        ];
        
        const result = await pool.query(query, values);
        res.status(201).json({ mensaje: 'Corte guardado correctamente', id: result.rows[0].id });

    } catch (err) {
        console.error("ERROR EN CORTE:", err);
        res.status(500).json({ error: err.message });
    }
});


// ======================================================================
// INICIO DEL SERVIDOR
// ======================================================================
app.listen(PORT, () => {
    console.log(`🚀 Servidor Olimpollo Pro corriendo en el puerto ${PORT}`);
});
