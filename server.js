// ----------------------------------------------------------------------
// server.js - Back-End para Olimpollo (VERSIÓN FINAL Y COMPLETA)
// ----------------------------------------------------------------------

const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors'); 
const { Pool } = require('pg'); 
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;

const JWT_SECRET = process.env.JWT_SECRET || 'miclavesecretaultraseguraolimpollos';


// ======================================================================
// CONFIGURACIÓN DE LA BASE DE DATOS REAL (POSTGRESQL)
// *Configuración para entorno local en Mac/Windows*
// ======================================================================
const isProduction = process.env.NODE_ENV === 'production';

const connectionString = `postgresql://${process.env.DB_USER}:${process.env.DB_PASSWORD}@${process.env.DB_HOST}/${process.env.DB_DATABASE}`;

const pool = new Pool({
    connectionString: isProduction ? process.env.DATABASE_URL : connectionString,
    ssl: isProduction ? { rejectUnauthorized: false } : false
});

pool.query('SELECT NOW()', (err, res) => {
    if (err) {
        console.error('Error al conectar con la base de datos:', err);
    } else {
        console.log('Conexión exitosa a PostgreSQL establecida.');
    }
});


// ======================================================================
// MIDDLEWARE (Sin verificación JWT, solo lectura de JSON y CORS)
// ======================================================================
app.use(cors()); 
app.use(bodyParser.json()); 


// ======================================================================
// ENDPOINT DE AUTENTICACIÓN (LOGIN)
// ======================================================================

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const result = await pool.query('SELECT id, password_hash, rol FROM Usuarios WHERE username = $1', [username]);
        
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Usuario o contraseña incorrectos.' });
        }

        const user = result.rows[0];
        const match = await bcrypt.compare(password, user.password_hash);
        
        if (!match) {
            return res.status(401).json({ error: 'Usuario o contraseña incorrectos.' });
        }

        const token = jwt.sign(
            { userId: user.id, username: username, rol: user.rol }, 
            JWT_SECRET, 
            { expiresIn: '8h' } 
        );

        res.status(200).json({ 
            token: token, 
            rol: user.rol,
            mensaje: 'Inicio de sesión exitoso.'
        });

    } catch (err) {
        console.error('Error en el proceso de login:', err);
        res.status(500).json({ error: 'Error del servidor al intentar iniciar sesión.' });
    }
});


// ======================================================================
// ENDPOINTS DE GESTIÓN DE USUARIOS (CRUD)
// ======================================================================

// [GET] /api/usuarios - Listar todos los usuarios
app.get('/api/usuarios', async (req, res) => {
    try {
        const query = 'SELECT id, username, rol FROM Usuarios ORDER BY id';
        const result = await pool.query(query);
        res.status(200).json(result.rows);
    } catch (err) {
        console.error('Error al obtener usuarios:', err);
        res.status(500).json({ error: 'Error del servidor al obtener la lista de usuarios.' });
    }
});

// [POST] /api/usuarios - Crear un nuevo usuario
app.post('/api/usuarios', async (req, res) => {
    const { username, password, rol } = req.body;

    if (!username || !password || !rol) {
        return res.status(400).json({ error: 'Faltan campos obligatorios: username, password y rol.' });
    }

    try {
        const existingUser = await pool.query('SELECT id FROM Usuarios WHERE username = $1', [username]);
        if (existingUser.rows.length > 0) {
            return res.status(400).json({ error: 'El nombre de usuario ya está en uso.' });
        }

        const saltRounds = 10;
        const password_hash = await bcrypt.hash(password, saltRounds);

        const query = 'INSERT INTO Usuarios (username, password_hash, rol) VALUES ($1, $2, $3) RETURNING id, username, rol';
        const values = [username, password_hash, rol];
        const result = await pool.query(query, values);

        res.status(201).json(result.rows[0]); 
    } catch (err) {
        console.error('Error al crear usuario:', err);
        res.status(500).json({ error: 'Error del servidor al crear el usuario.' });
    }
});

// [DELETE] /api/usuarios/:id - Eliminar un usuario
app.delete('/api/usuarios/:id', async (req, res) => {
    const id = parseInt(req.params.id, 10);

    if (id === 1) { 
         return res.status(403).json({ error: 'No se puede eliminar el usuario administrador principal.' });
    }

    try {
        const result = await pool.query('DELETE FROM Usuarios WHERE id = $1 RETURNING id', [id]);
        
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado.' });
        }
        
        res.status(204).send(); 
    } catch (err) {
        console.error('Error al eliminar usuario:', err);
        res.status(500).json({ error: 'Error del servidor al eliminar el usuario.' });
    }
});


// ======================================================================
// ENDPOINTS DE MENÚ (POS Y GESTIÓN)
// ======================================================================

// [GET] /api/menu/pos - Obtiene todos los productos y opciones para la interfaz de pedidos
app.get('/api/menu/pos', async (req, res) => {
    try {
        const productosResult = await pool.query('SELECT id, nombre_venta, categoria, CAST(precio_base AS TEXT) AS precio_base, grupos_modificadores FROM menu_productos ORDER BY categoria, nombre_venta');

        const opcionesResult = await pool.query('SELECT id, nombre_opcion, valor, CAST(precio_adicional AS TEXT) AS precio_adicional FROM menu_opciones ORDER BY nombre_opcion, valor');

        const opcionesOrganizadas = opcionesResult.rows.reduce((acc, opcion) => {
            if (!acc[opcion.nombre_opcion]) {
                acc[opcion.nombre_opcion] = [];
            }
            opcion.precio_adicional = parseFloat(opcion.precio_adicional); 
            acc[opcion.nombre_opcion].push(opcion);
            return acc;
        }, {});

        const productos = productosResult.rows.map(p => ({
            ...p,
            precio_base: parseFloat(p.precio_base)
        }));

        res.status(200).json({
            productos: productos,
            opciones: opcionesOrganizadas
        });

    } catch (err) {
        console.error('Error al obtener el menú POS:', err);
        res.status(500).json({ error: 'Error del servidor al cargar el menú.' });
    }
});

// --- CRUD: MENU_PRODUCTOS (Productos de Venta) ---

// [GET] /api/menu/productos - Listar todos los productos (Para selector de recetas)
app.get('/api/menu/productos', async (req, res) => {
    try {
        const result = await pool.query('SELECT id, nombre_venta, categoria, receta_id FROM menu_productos ORDER BY nombre_venta');
        res.status(200).json(result.rows);
    } catch (err) {
        console.error('Error al obtener productos de menú:', err);
        res.status(500).json({ error: 'Error del servidor al cargar la lista de productos.' });
    }
});

// [POST] /api/menu/productos - Crear un nuevo producto
app.post('/api/menu/productos', async (req, res) => {
    const { nombre_venta, precio_base, categoria, receta_id, descripcion, grupos_modificadores } = req.body;
    
    if (!nombre_venta || !precio_base || !categoria) {
        return res.status(400).json({ error: 'Faltan campos obligatorios: nombre, precio y categoría.' });
    }
    
    try {
        const query = `INSERT INTO menu_productos (nombre_venta, precio_base, categoria, receta_id, descripcion, grupos_modificadores) 
                       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`;
        const values = [nombre_venta, parseFloat(precio_base), categoria, receta_id || null, descripcion, grupos_modificadores || ''];
        const result = await pool.query(query, values);
        
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('Error al crear producto de menú:', err);
        res.status(500).json({ error: 'Error del servidor al crear el producto.' });
    }
});

// [PUT] /api/menu/productos/:id - Actualizar un producto (Incluye vinculación a receta)
app.put('/api/menu/productos/:id', async (req, res) => {
    const id = parseInt(req.params.id, 10);
    const { nombre_venta, precio_base, categoria, receta_id, descripcion, grupos_modificadores } = req.body;
    
    if (!nombre_venta || !precio_base || !categoria) {
        return res.status(400).json({ error: 'Faltan campos obligatorios.' });
    }

    try {
        const query = `UPDATE menu_productos SET nombre_venta=$1, precio_base=$2, categoria=$3, receta_id=$4, descripcion=$5, grupos_modificadores=$6 
                       WHERE id=$7 RETURNING *`;
        const values = [nombre_venta, parseFloat(precio_base), categoria, receta_id || null, descripcion, grupos_modificadores || '', id];
        const result = await pool.query(query, values);

        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Producto no encontrado.' });
        }
        res.status(200).json(result.rows[0]);
    } catch (err) {
        console.error('Error al actualizar producto de menú:', err);
        res.status(500).json({ error: 'Error del servidor al actualizar el producto.' });
    }
});

// [DELETE] /api/menu/productos/:id - Eliminar un producto
app.delete('/api/menu/productos/:id', async (req, res) => {
    const id = parseInt(req.params.id, 10);
    try {
        const result = await pool.query('DELETE FROM menu_productos WHERE id = $1 RETURNING id', [id]);
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Producto no encontrado.' });
        }
        res.status(204).send();
    } catch (err) {
        console.error('Error al eliminar producto de menú:', err);
        res.status(500).json({ error: 'Error del servidor al eliminar el producto.' });
    }
});


// --- CRUD: MENU_OPCIONES (Modificadores/Salsas) ---

// [GET] /api/menu/opciones - Listar opciones por nombre_opcion (ej: ?nombre_opcion=Salsa)
app.get('/api/menu/opciones', async (req, res) => {
    const { nombre_opcion } = req.query;
    try {
        const query = 'SELECT id, nombre_opcion, valor, CAST(precio_adicional AS TEXT) AS precio_adicional FROM menu_opciones WHERE nombre_opcion = $1 ORDER BY id';
        const result = await pool.query(query, [nombre_opcion || 'Salsa']);
        
        const opciones = result.rows.map(op => ({...op, precio_adicional: parseFloat(op.precio_adicional)}));
        res.status(200).json(opciones);
    } catch (err) {
        console.error('Error al obtener opciones:', err);
        res.status(500).json({ error: 'Error del servidor al cargar opciones.' });
    }
});

// [POST] /api/menu/opciones - Crear una nueva opción
app.post('/api/menu/opciones', async (req, res) => {
    const { nombre_opcion, valor, precio_adicional } = req.body;
    
    if (!nombre_opcion || !valor) {
        return res.status(400).json({ error: 'Faltan campos obligatorios: nombre_opcion y valor.' });
    }
    
    try {
        const query = 'INSERT INTO menu_opciones (nombre_opcion, valor, precio_adicional) VALUES ($1, $2, $3) RETURNING *';
        const values = [nombre_opcion, valor, parseFloat(precio_adicional) || 0.00];
        const result = await pool.query(query, values);
        
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('Error al crear opción:', err);
        res.status(500).json({ error: 'Error del servidor al crear la opción.' });
    }
});

// [DELETE] /api/menu/opciones/:id - Eliminar una opción
app.delete('/api/menu/opciones/:id', async (req, res) => {
    const id = parseInt(req.params.id, 10);
    try {
        const result = await pool.query('DELETE FROM menu_opciones WHERE id = $1 RETURNING id', [id]);
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Opción no encontrada.' });
        }
        res.status(204).send();
    } catch (err) {
        console.error('Error al eliminar opción:', err);
        res.status(500).json({ error: 'Error del servidor al eliminar la opción.' });
    }
});

// [DELETE] /api/menu/opciones/grupo/:nombre - Eliminar un grupo completo de modificadores
app.delete('/api/menu/opciones/grupo/:nombre', async (req, res) => {
    const nombreGrupo = req.params.nombre;
    try {
        // Borramos todas las opciones que tengan este nombre_opcion
        const result = await pool.query('DELETE FROM menu_opciones WHERE nombre_opcion = $1 RETURNING *', [nombreGrupo]);
        
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Grupo no encontrado.' });
        }
        res.status(200).json({ mensaje: `Grupo '${nombreGrupo}' eliminado con sus ${result.rowCount} opciones.` });
    } catch (err) {
        console.error('Error al eliminar grupo:', err);
        res.status(500).json({ error: 'Error del servidor al eliminar el grupo.' });
    }
});

// ======================================================================
// ENDPOINTS DE INVENTARIO (CON CATEGORÍA, FILTROS Y REGISTRO FÍSICO)
// ======================================================================

// [GET] /api/inventario - Obtener todo el inventario con categoría, estado y filtros
app.get('/api/inventario', async (req, res) => {
    const { categoria, estado } = req.query; // Captura los parámetros de filtro

    let whereClauses = [];
    let values = [];
    let paramIndex = 1;

    // 1. Lógica de Filtrado por Categoría
    if (categoria) {
        whereClauses.push(`categoria = $${paramIndex++}`);
        values.push(categoria);
    }

    // 2. Lógica de Filtrado por Estado (usando el CASE WHEN del SQL)
    if (estado) {
        let estadoCondition;
        if (estado === 'Agotado') {
            estadoCondition = 'cantidad <= 0';
        } else if (estado === 'Requiere re-stock') {
            estadoCondition = 'cantidad > 0 AND cantidad <= stock_minimo';
        } else if (estado === 'En stock') {
            estadoCondition = 'cantidad > stock_minimo';
        }
        
        if (estadoCondition) {
            whereClauses.push(`(${estadoCondition})`);
        }
    }
    
    // 3. Construir la consulta SQL
    const whereClause = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

    const query = `
        SELECT 
            id, 
            nombre, 
            cantidad, 
            unidad,
            stock_minimo,
            categoria, 
            CASE
                WHEN cantidad <= 0 THEN 'Agotado'
                WHEN cantidad <= stock_minimo THEN 'Requiere re-stock'
                ELSE 'En stock'
            END AS estado
        FROM Insumos 
        ${whereClause} 
        ORDER BY id;
    `;

    try {
        const result = await pool.query(query, values);
        res.status(200).json(result.rows);
    } catch (err) {
        console.error('Error al obtener inventario con filtros:', err);
        res.status(500).json({ error: 'Error del servidor al aplicar filtros.' });
    }
});


// [POST] /api/inventario - Agregar un nuevo insumo con categoría
app.post('/api/inventario', async (req, res) => {
    const { nombre, cantidad, unidad = 'Unidad', stock_minimo = 0, categoria = 'Materia Prima' } = req.body; 
    
    if (!nombre || cantidad === undefined || isNaN(parseInt(cantidad))) {
        return res.status(400).json({ error: 'Faltan nombre, cantidad o stock mínimo válidos.' });
    }

    try {
        const query = 'INSERT INTO Insumos (nombre, cantidad, unidad, stock_minimo, categoria) VALUES ($1, $2, $3, $4, $5) RETURNING *';
        const values = [nombre, parseInt(cantidad, 10), unidad, parseInt(stock_minimo, 10), categoria];
        const result = await pool.query(query, values);
        
        res.status(201).json(result.rows[0]); 
    } catch (err) {
        console.error('Error al agregar insumo:', err); 
        res.status(500).json({ error: 'Error del servidor al agregar el insumo.' });
    }
});


// [PUT] /api/inventario/:id - Actualizar un producto con categoría
app.put('/api/inventario/:id', async (req, res) => {
    const id = parseInt(req.params.id, 10);
    const { nombre, cantidad, unidad, stock_minimo, categoria } = req.body; 

    if (!nombre || cantidad === undefined || unidad === undefined || stock_minimo === undefined || categoria === undefined) {
        return res.status(400).json({ error: 'Faltan campos obligatorios para actualizar.' });
    }

    try {
        const query = 'UPDATE Insumos SET nombre = $1, cantidad = $2, unidad = $3, stock_minimo = $4, categoria = $5 WHERE id = $6 RETURNING *';
        const values = [nombre, parseInt(cantidad, 10), unidad, parseInt(stock_minimo, 10), categoria, id];
        
        const result = await pool.query(query, values);

        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Insumo no encontrado.' });
        }

        res.status(200).json(result.rows[0]);
    } catch (err) {
        console.error('Error al actualizar insumo:', err);
        res.status(500).json({ error: 'Error del servidor al actualizar el insumo.' });
    }
});

// [DELETE] /api/inventario/:id - Eliminar un insumo (CORREGIDO PARA RESTRICCIÓN DE RECETAS)
app.delete('/api/inventario/:id', async (req, res) => {
    const id = parseInt(req.params.id, 10);

    try {
        const result = await pool.query('DELETE FROM Insumos WHERE id = $1 RETURNING id', [id]);
        
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Insumo no encontrado.' });
        }
        
        res.status(204).send(); 
    } catch (err) {
        console.error('Error al eliminar insumo:', err);
        
        if (err.code === '23503') {
            return res.status(409).json({ 
                error: 'Restricción de receta',
                mensaje: 'Este insumo no puede eliminarse porque está siendo utilizado en una o más recetas. Primero elimine la receta que lo usa.' 
            });
        }
        
        res.status(500).json({ error: 'Error del servidor al eliminar el insumo.' });
    }
});

// [POST] /api/inventario/guardar - Guarda el estado actual del inventario
app.post('/api/inventario/guardar', async (req, res) => {
    const client = await pool.connect();
    try {
        await client.query('BEGIN'); // Iniciar la transacción

        // 1. Obtener todos los insumos del inventario actual
        const inventarioActualQuery = `
            SELECT id, nombre, cantidad, unidad, categoria 
            FROM Insumos;
        `;
        const result = await pool.query(inventarioActualQuery);
        const insumos = result.rows;

        if (insumos.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'No hay insumos para registrar.' });
        }

        // 2. Preparar la inserción masiva en Registro_Inventario
        const placeholders = insumos.map((_, i) => 
            `($${i * 5 + 1}, $${i * 5 + 2}, $${i * 5 + 3}, $${i * 5 + 4}, $${i * 5 + 5})`
        ).join(', ');

        let values = [];
        insumos.forEach(insumo => {
            values.push(
                insumo.id, 
                insumo.nombre, 
                insumo.cantidad, 
                insumo.unidad, 
                insumo.categoria
            );
        });

        // 3. Ejecutar la inserción
        const insertQuery = `
            INSERT INTO Registro_Inventario 
                (insumo_id, nombre_insumo, cantidad_registrada, unidad_medida, categoria) 
            VALUES 
                ${placeholders} 
            RETURNING fecha_registro;
        `;
        
        await client.query(insertQuery, values);
        
        await client.query('COMMIT'); // Finalizar la transacción
        res.status(201).json({ mensaje: 'Inventario físico registrado exitosamente.' });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Error al guardar inventario físico:', err);
        res.status(500).json({ error: 'Error al procesar el guardado del inventario.' });
    } finally {
        client.release();
    }
});

// ======================================================================
// ENDPOINTS DE COMPRAS (RE-STOCK)
// ======================================================================

// [POST] /api/compras - Registrar nueva compra y aumentar stock
app.post('/api/compras', async (req, res) => {
    const { proveedor, items, total_compra } = req.body;
    // items debe ser un array: [{ insumo_id, cantidad, costo_unitario }, ...]

    if (!items || items.length === 0) {
        return res.status(400).json({ error: 'La compra debe tener al menos un insumo.' });
    }

    const client = await pool.connect();

    try {
        await client.query('BEGIN'); // Iniciar transacción segura

        // 1. Insertar la cabecera de la compra
        const compraQuery = `
            INSERT INTO compras (proveedor, total_compra) 
            VALUES ($1, $2) 
            RETURNING id, fecha_compra
        `;
        const compraRes = await client.query(compraQuery, [proveedor || 'General', total_compra]);
        const compraId = compraRes.rows[0].id;

        // 2. Procesar cada item
        for (const item of items) {
            const { insumo_id, cantidad, costo_unitario } = item;
            const subtotal = cantidad * costo_unitario;

            // A. Insertar en detalle de compra
            await client.query(
                `INSERT INTO compra_items (compra_id, insumo_id, cantidad_comprada, costo_unitario, subtotal)
                 VALUES ($1, $2, $3, $4, $5)`,
                [compraId, insumo_id, cantidad, costo_unitario, subtotal]
            );

            // B. ACTUALIZAR INVENTARIO (Sumar stock)
            await client.query(
                `UPDATE insumos SET cantidad = cantidad + $1 WHERE id = $2`,
                [cantidad, insumo_id]
            );
        }

        await client.query('COMMIT'); // Confirmar cambios
        res.status(201).json({ mensaje: 'Compra registrada y stock actualizado.', compraId });

    } catch (err) {
        await client.query('ROLLBACK'); // Cancelar si algo falla
        console.error('Error al registrar compra:', err);
        res.status(500).json({ error: 'Error al procesar la compra.' });
    } finally {
        client.release();
    }
});


// ======================================================================
// ENDPOINTS DE PEDIDOS (TABLAS PEDIDOS y PEDIDO_ITEMS)
// ======================================================================

// [GET] /api/pedidos - LISTA CON FILTROS Y ZONA HORARIA
// [GET] /api/pedidos - LISTA CON ZONA HORARIA CORREGIDA
app.get('/api/pedidos', async (req, res) => {
    // Actualizar estados pendientes viejos
    await pool.query(`UPDATE pedidos SET estado = 'Entregado' WHERE estado = 'Pendiente' AND fecha_creacion < NOW() - INTERVAL '1 hour';`);

    const { canal, estado, fechaInicio, fechaFin } = req.query; 
    let whereClauses = [];
    let values = [];
    let paramIndex = 1;

    // Filtros
    if (canal && canal !== 'Todos') {
        whereClauses.push(`p.canal_venta = $${paramIndex++}`);
        values.push(canal);
    }
    if (estado) {
        whereClauses.push(`p.estado = $${paramIndex++}`);
        values.push(estado);
    }
    
    // 🚨 CORRECCIÓN DE FECHAS: Salto directo a Hermosillo
    if (fechaInicio) {
        whereClauses.push(`(p.fecha_creacion AT TIME ZONE 'America/Hermosillo')::date >= $${paramIndex++}`);
        values.push(fechaInicio);
    }
    if (fechaFin) {
        whereClauses.push(`(p.fecha_creacion AT TIME ZONE 'America/Hermosillo')::date <= $${paramIndex++}`);
        values.push(fechaFin);
    }
    
    const whereClause = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';
    
    try {
        const query = `
            SELECT 
                p.id, p.cliente, p.estado, CAST(p.total AS TEXT) AS total, 
                p.fecha_creacion, p.canal_venta,
                json_agg(json_build_object(
                    'nombre_producto', pi.nombre_producto, 
                    'cantidad', pi.cantidad, 
                    'precio_unitario', CAST(pi.precio_unitario AS TEXT)
                )) AS items 
            FROM pedidos p 
            JOIN pedido_items pi ON p.id = pi.pedido_id 
            ${whereClause} 
            GROUP BY p.id 
            ORDER BY p.fecha_creacion DESC;
        `;
        const result = await pool.query(query, values);
        const pedidos = result.rows.map(p => ({ 
            ...p, 
            total: parseFloat(p.total), 
            items: p.items.map(i => ({ ...i, precio_unitario: parseFloat(i.precio_unitario) })) 
        }));
        res.status(200).json(pedidos);
    } catch (err) {
        console.error('Error al obtener pedidos:', err);
        res.status(500).json({ error: 'Error del servidor al obtener los pedidos.' });
    }
});

// [DELETE] /api/pedidos/:id - Eliminar pedido (CRUD)
app.delete('/api/pedidos/:id', async (req, res) => {
    const id = parseInt(req.params.id, 10);

    try {
        const result = await pool.query('DELETE FROM Pedidos WHERE id = $1 RETURNING id', [id]);
        
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Pedido no encontrado.' });
        }
        
        res.status(204).send(); 
    } catch (err) {
        console.error('Error al eliminar pedido:', err);
        res.status(500).json({ error: 'Error del servidor al eliminar el pedido.' });
    }
});

// [POST] /api/pedidos
app.post('/api/pedidos', async (req, res) => {
    const { cliente, items, canal_venta, total_ajustado } = req.body;
    if (!cliente || !items || items.length === 0) {
        return res.status(400).json({ error: 'Faltan datos de cliente o items.' });
    }

    const totalCalculado = items.reduce((sum, item) => sum + (item.cantidad * item.precio_unitario), 0);
    const totalFinal = total_ajustado ?? totalCalculado;

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const pedidoQuery = 'INSERT INTO pedidos (cliente, total, canal_venta) VALUES ($1, $2, $3) RETURNING id';
        const pedidoResult = await client.query(pedidoQuery, [cliente, totalFinal, canal_venta || 'OyR']);
        const pedidoId = pedidoResult.rows[0].id;

        for (const item of items) {
            const itemQuery = `
                INSERT INTO pedido_items 
                    (pedido_id, menu_producto_id, nombre_producto, cantidad, precio_unitario) 
                VALUES ($1, $2, $3, $4, $5)`;
            const itemValues = [pedidoId, item.menu_producto_id, item.nombre_producto_completo, item.cantidad, item.precio_unitario];
            await client.query(itemQuery, itemValues);
        }

        await client.query('COMMIT');
        res.status(201).json({ id: pedidoId, cliente, total: totalFinal });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Error al crear pedido (ROLLBACK):', err);
        res.status(500).json({ error: 'Error del servidor al crear el pedido.' });
    } finally {
        client.release();
    }
});


// server.js - Reemplazar endpoint PUT /api/pedidos/:id

app.put('/api/pedidos/:id', async (req, res) => {
    const id = parseInt(req.params.id, 10);
    const { estado: nuevoEstado } = req.body;
    const client = await pool.connect();

    if (!nuevoEstado) {
        client.release();
        return res.status(400).json({ error: 'Falta el nuevo estado del pedido.' });
    }

    try {
        await client.query('BEGIN');

        // Solo descontamos inventario si el estado cambia a 'Entregado'
        if (nuevoEstado === 'Entregado') {
            
            // 1. Obtener los items del pedido (Sin comillas en tabla)
            const itemsResult = await client.query(
                'SELECT menu_producto_id, nombre_producto, cantidad FROM pedido_items WHERE pedido_id = $1', [id]
            );
            
            for (const item of itemsResult.rows) {
                // --- A. DESCUENTO DE LA RECETA BASE ---
                const recetaResult = await client.query(
                    'SELECT receta_id FROM menu_productos WHERE id = $1', [item.menu_producto_id]
                );

                if (recetaResult.rows.length > 0 && recetaResult.rows[0].receta_id) {
                    const recetaId = recetaResult.rows[0].receta_id;
                    const insumosResult = await client.query(
                        'SELECT insumo_id, cantidad_necesaria FROM receta_insumo WHERE receta_id = $1', [recetaId]
                    );

                    for (const insumo of insumosResult.rows) {
                        const cantidadADescontar = insumo.cantidad_necesaria * item.cantidad;
                        await client.query(
                            'UPDATE insumos SET cantidad = cantidad - $1 WHERE id = $2', 
                            [cantidadADescontar, insumo.insumo_id]
                        );
                    }
                }

                // --- B. DESCUENTO DE MODIFICADORES (OPCIONES) ---
                const match = item.nombre_producto.match(/\((.*)\)/);
                
                if (match) {
                    const modificadoresStr = match[1];
                    const modificadoresLista = modificadoresStr.split(',').map(m => m.trim());

                    for (const nombreModificador of modificadoresLista) {
                        // Verificamos si el modificador tiene configuración de inventario
                        const opcionResult = await client.query(
                            'SELECT insumo_id, cantidad_insumo FROM menu_opciones WHERE valor = $1 LIMIT 1',
                            [nombreModificador]
                        );

                        if (opcionResult.rows.length > 0) {
                            const { insumo_id, cantidad_insumo } = opcionResult.rows[0];
                            
                            // Solo descontamos si existen datos válidos (no nulos)
                            if (insumo_id && cantidad_insumo) {
                                const totalModificador = parseFloat(cantidad_insumo) * item.cantidad;
                                await client.query(
                                    'UPDATE insumos SET cantidad = cantidad - $1 WHERE id = $2',
                                    [totalModificador, insumo_id]
                                );
                            }
                        }
                    }
                }
            }
        }
        
        await client.query('UPDATE pedidos SET estado = $1 WHERE id = $2', [nuevoEstado, id]);

        await client.query('COMMIT');
        res.status(200).json({ id, estado: nuevoEstado, mensaje: 'Pedido actualizado e inventario descontado.' });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Error al actualizar pedido (ROLLBACK):', err);
        // Enviamos el mensaje de error exacto para que puedas verlo en la consola del navegador si falla
        res.status(500).json({ error: 'Error del servidor: ' + err.message });
    } finally {
        client.release();
    }
});

// ======================================================================
// ENDPOINTS DE RECETAS (TABLAS RECETAS y RECETA_INSUMO)
// ======================================================================

// [GET] /api/recetas - Obtener todas las recetas con sus ingredientes
app.get('/api/recetas', async (req, res) => {
    try {
        const query = `
            SELECT 
                r.id, r.nombre, r.descripcion, r.pasos,
                COALESCE(
                    (SELECT json_agg(json_build_object(
                        'insumo_id', ri.insumo_id,
                        'nombre', i.nombre,
                        'cantidad_necesaria', CAST(ri.cantidad_necesaria AS TEXT),
                        'unidad_medida', ri.unidad_medida
                    ))
                    FROM receta_insumo ri
                    JOIN Insumos i ON ri.insumo_id = i.id
                    WHERE ri.receta_id = r.id),
                    '[]'::json
                ) AS ingredientes
            FROM Recetas r
            ORDER BY r.nombre;
        `;
        const result = await pool.query(query);

        const recetas = result.rows.map(receta => ({
            ...receta,
            ingredientes: receta.ingredientes.map(ing => ({
                ...ing,
                cantidad_necesaria: parseFloat(ing.cantidad_necesaria)
            }))
        }));

        res.status(200).json(recetas);
    } catch (err) {
        console.error('Error al obtener recetas:', err);
        res.status(500).json({ error: 'Error del servidor al obtener las recetas.' });
    }
});


// [POST] /api/recetas - Crear nueva receta y vincular a producto
app.post('/api/recetas', async (req, res) => {
    const { nombre, descripcion, pasos, ingredientes, producto_venta_id } = req.body;
    const client = await pool.connect();

    if (!nombre || !ingredientes || ingredientes.length === 0) {
        return res.status(400).json({ error: 'Faltan nombre o ingredientes.' });
    }

    try {
        await client.query('BEGIN');

        const recetaQuery = 'INSERT INTO Recetas (nombre, descripcion, pasos) VALUES ($1, $2, $3) RETURNING id';
        const recetaResult = await client.query(recetaQuery, [nombre, descripcion, pasos]);
        const recetaId = recetaResult.rows[0].id;

        for (const ing of ingredientes) {
            const { insumo_id, cantidad_necesaria, unidad_medida } = ing;
            const insertInsumoQuery = 'INSERT INTO receta_insumo (receta_id, insumo_id, cantidad_necesaria, unidad_medida) VALUES ($1, $2, $3, $4)';
            await client.query(insertInsumoQuery, [recetaId, parseInt(insumo_id), parseFloat(cantidad_necesaria), unidad_medida]);
        }
        
        if (producto_venta_id) {
            const updateProductQuery = 'UPDATE menu_productos SET receta_id = $1 WHERE id = $2';
            await client.query(updateProductQuery, [recetaId, parseInt(producto_venta_id)]);
        }

        await client.query('COMMIT');
        res.status(201).json({ id: recetaId, nombre, mensaje: 'Receta creada y vinculada con éxito.' });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Error al crear receta (ROLLBACK):', err);
        res.status(500).json({ error: 'Error del servidor al crear la receta: ' + err.message });
    } finally {
        client.release();
    }
});


// [PUT] /api/recetas/:id - Actualizar una receta y su vinculación
app.put('/api/recetas/:id', async (req, res) => {
    const id = parseInt(req.params.id, 10);
    const { nombre, descripcion, pasos, ingredientes, producto_venta_id } = req.body;
    const client = await pool.connect();

    if (!nombre || !ingredientes || ingredientes.length === 0) {
        return res.status(400).json({ error: 'Faltan campos obligatorios.' });
    }

    try {
        await client.query('BEGIN');

        await client.query('UPDATE recetas SET nombre = $1, descripcion = $2, pasos = $3 WHERE id = $4', [nombre, descripcion, pasos, id]);

        await client.query('DELETE FROM receta_insumo WHERE receta_id = $1', [id]);
        for (const ing of ingredientes) {
            const { insumo_id, cantidad_necesaria, unidad_medida } = ing;
            const insertInsumoQuery = 'INSERT INTO receta_insumo (receta_id, insumo_id, cantidad_necesaria, unidad_medida) VALUES ($1, $2, $3, $4)';
            await client.query(insertInsumoQuery, [id, parseInt(insumo_id), parseFloat(cantidad_necesaria), unidad_medida]);
        }

        await client.query('UPDATE menu_productos SET receta_id = NULL WHERE receta_id = $1', [id]);

        if (producto_venta_id) {
            await client.query('UPDATE menu_productos SET receta_id = $1 WHERE id = $2', [id, parseInt(producto_venta_id)]);
        }

        await client.query('COMMIT');
        res.status(200).json({ id, mensaje: 'Receta y vinculación actualizadas.' });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Error al actualizar receta (ROLLBACK):', err);
        res.status(500).json({ error: 'Error del servidor al actualizar la receta: ' + err.message });
    } finally {
        client.release();
    }
});


// [DELETE] /api/recetas/:id - Eliminar una receta
app.delete('/api/recetas/:id', async (req, res) => {
    const id = parseInt(req.params.id, 10);
    const client = await pool.connect();
    
    try {
        await client.query('BEGIN');

        await client.query('UPDATE "menu_productos" SET receta_id = NULL WHERE receta_id = $1', [id]);
        await client.query('DELETE FROM receta_insumo WHERE receta_id = $1', [id]);
        const result = await client.query('DELETE FROM recetas WHERE id = $1 RETURNING id', [id]);
        
        if (result.rowCount === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Receta no encontrada.' });
        }
        
        await client.query('COMMIT');
        res.status(204).send();
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Error al eliminar receta:', err);
        res.status(500).json({ error: 'Error del servidor al eliminar la receta.' });
    } finally {
        client.release();
    }
});


// ======================================================================
// ENDPOINTS DE REPORTES
// ======================================================================

// [GET] /api/reportes/ventas - Generar reporte de ventas (CON ZONA HORARIA HERMOSILLO)
// [GET] /api/reportes/ventas - CORREGIDO (Salto directo a Hermosillo)
app.get('/api/reportes/ventas', async (req, res) => {
    const { fechaInicio, fechaFin } = req.query;

    if (!fechaInicio || !fechaFin) {
        return res.status(400).json({ error: 'Se requieren fechaInicio y fechaFin.' });
    }

    try {
        // CORRECCIÓN: Usamos un solo AT TIME ZONE para obtener la hora local real
        const query = `
            SELECT 
                COUNT(id) AS total_pedidos, 
                SUM(total) AS ventas_totales
            FROM Pedidos
            WHERE (fecha_creacion AT TIME ZONE 'America/Hermosillo')::date >= $1 
              AND (fecha_creacion AT TIME ZONE 'America/Hermosillo')::date <= $2
              AND estado = 'Entregado';
        `;
        const values = [fechaInicio, fechaFin];
        const result = await pool.query(query, values);
        
        const reporte = result.rows[0];
        
        res.status(200).json({
            fechaInicio: fechaInicio,
            fechaFin: fechaFin,
            total_pedidos: parseInt(reporte.total_pedidos || 0),
            ventas_totales: parseFloat(reporte.ventas_totales || 0).toFixed(2)
        });

    } catch (err) {
        console.error('Error al generar reporte de ventas:', err);
        res.status(500).json({ error: 'Error del servidor al generar el reporte.' });
    }
});

// [GET] /api/reportes/inventario - Obtener registros históricos de inventario por fecha
app.get('/api/reportes/inventario', async (req, res) => {
    const { fecha } = req.query; 

    if (!fecha) {
        return res.status(400).json({ error: 'Se requiere la fecha para obtener el registro de inventario.' });
    }

    try {
        // 🚨 CORRECCIÓN: Usar 'fecha_registro' que es la columna correcta en esta tabla
        const query = `
            SELECT 
                fecha_registro,
                nombre_insumo,
                cantidad_registrada,
                unidad_medida,
                categoria
            FROM Registro_Inventario
            WHERE fecha_registro::date = $1
            ORDER BY nombre_insumo;
        `;
        const result = await pool.query(query, [fecha]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ mensaje: 'No se encontraron registros de inventario para la fecha seleccionada.' });
        }

        res.status(200).json(result.rows);

    } catch (err) {
        console.error('Error al generar reporte de inventario histórico:', err);
        res.status(500).json({ error: 'Error del servidor al obtener el registro de inventario: ' + err.message });
    }
});
// [GET] /api/reportes/platillos - Conteo de platillos vendidos
app.get('/api/reportes/platillos', async (req, res) => {
    const { fechaInicio, fechaFin } = req.query;

    if (!fechaInicio || !fechaFin) {
        return res.status(400).json({ error: 'Se requieren fechaInicio y fechaFin.' });
    }

    try {
        // Esta consulta une los items vendidos con el nombre "limpio" del producto base
        const query = `
            SELECT 
                mp.nombre_venta AS producto, 
                SUM(pi.cantidad) AS cantidad_vendida,
                SUM(pi.cantidad * pi.precio_unitario) AS ingreso_generado
            FROM pedido_items pi
            JOIN pedidos p ON pi.pedido_id = p.id
            JOIN menu_productos mp ON pi.menu_producto_id = mp.id
            WHERE p.estado = 'Entregado'
  AND (p.fecha_creacion AT TIME ZONE 'UTC' AT TIME ZONE 'America/Hermosillo')::date >= $1 
  AND (p.fecha_creacion AT TIME ZONE 'UTC' AT TIME ZONE 'America/Hermosillo')::date <= $2
            GROUP BY mp.nombre_venta
            ORDER BY cantidad_vendida DESC;
        `;
        
        const values = [fechaInicio, fechaFin];
        const result = await pool.query(query, values);
        
        res.status(200).json(result.rows);

    } catch (err) {
        console.error('Error al generar reporte de platillos:', err);
        res.status(500).json({ error: 'Error del servidor: ' + err.message });
    }
});

// [GET] /api/reportes/insumos-teoricos - Cálculo de insumos teóricos basados en ventas
app.get('/api/reportes/insumos-teoricos', async (req, res) => {
    const { fechaInicio, fechaFin } = req.query;

    if (!fechaInicio || !fechaFin) {
        return res.status(400).json({ error: 'Se requieren fechaInicio y fechaFin.' });
    }

    try {
        const client = await pool.connect();
        
        // 1. Obtener todos los items vendidos en el periodo (solo entregados)
        const ventasQuery = `
            SELECT pi.menu_producto_id, pi.nombre_producto, pi.cantidad 
            FROM pedido_items pi
            JOIN pedidos p ON pi.pedido_id = p.id
            WHERE p.estado = 'Entregado'
  AND (p.fecha_creacion AT TIME ZONE 'UTC' AT TIME ZONE 'America/Hermosillo')::date >= $1 
  AND (p.fecha_creacion AT TIME ZONE 'UTC' AT TIME ZONE 'America/Hermosillo')::date <= $2
        `;
        const ventasResult = await client.query(ventasQuery, [fechaInicio, fechaFin]);
        const ventas = ventasResult.rows;

        // 2. Obtener mapa de Recetas (Producto -> Insumos)
        const recetasQuery = `
            SELECT mp.id as producto_id, ri.insumo_id, i.nombre as nombre_insumo, ri.cantidad_necesaria, ri.unidad_medida
            FROM menu_productos mp
            JOIN recetas r ON mp.receta_id = r.id
            JOIN receta_insumo ri ON r.id = ri.receta_id
            JOIN insumos i ON ri.insumo_id = i.id
        `;
        const recetasResult = await client.query(recetasQuery);
        
        // Organizar recetas por ID de producto para acceso rápido
        const recetasMap = {};
        recetasResult.rows.forEach(r => {
            if (!recetasMap[r.producto_id]) recetasMap[r.producto_id] = [];
            recetasMap[r.producto_id].push(r);
        });

        // 3. Obtener mapa de Modificadores (Nombre Opción -> Insumo)
        const opcionesQuery = `
            SELECT mo.valor, mo.insumo_id, i.nombre as nombre_insumo, mo.cantidad_insumo, mo.unidad_insumo
            FROM menu_opciones mo
            JOIN insumos i ON mo.insumo_id = i.id
            WHERE mo.insumo_id IS NOT NULL
        `;
        const opcionesResult = await client.query(opcionesQuery);
        
        // Organizar opciones por nombre (valor) para acceso rápido
        const opcionesMap = {};
        opcionesResult.rows.forEach(op => {
            // Usamos mayúsculas para evitar errores de coincidencia
            opcionesMap[op.valor.toUpperCase()] = op;
        });

        // 4. PROCESAMIENTO: Calcular totales
        const usoTotal = {}; // Objeto para acumular: { "Pollo": { cantidad: 500, unidad: 'g' } }

        ventas.forEach(venta => {
            const cantidadVenta = venta.cantidad;

            // A. Sumar insumos de la RECETA BASE
            if (recetasMap[venta.menu_producto_id]) {
                recetasMap[venta.menu_producto_id].forEach(insumo => {
                    const nombre = insumo.nombre_insumo;
                    const cantidad = parseFloat(insumo.cantidad_necesaria) * cantidadVenta;
                    
                    if (!usoTotal[nombre]) {
                        usoTotal[nombre] = { cantidad: 0, unidad: insumo.unidad_medida };
                    }
                    usoTotal[nombre].cantidad += cantidad;
                });
            }

            // B. Sumar insumos de los MODIFICADORES
            // Extraer texto entre paréntesis: "Boneless (BBQ, Ranch)" -> "BBQ, Ranch"
            const match = venta.nombre_producto.match(/\((.*)\)/);
            if (match) {
                const modificadores = match[1].split(',').map(m => m.trim().toUpperCase());
                
                modificadores.forEach(modNombre => {
                    const opData = opcionesMap[modNombre];
                    if (opData) {
                        const nombre = opData.nombre_insumo;
                        const cantidad = parseFloat(opData.cantidad_insumo) * cantidadVenta;

                        if (!usoTotal[nombre]) {
                            usoTotal[nombre] = { cantidad: 0, unidad: opData.unidad_insumo };
                        }
                        usoTotal[nombre].cantidad += cantidad;
                    }
                });
            }
        });

        client.release();

        // 5. Convertir objeto a array para enviar al front
        const reporteFinal = Object.keys(usoTotal).map(key => ({
            nombre_insumo: key,
            cantidad_total: usoTotal[key].cantidad,
            unidad: usoTotal[key].unidad
        })).sort((a, b) => b.cantidad_total - a.cantidad_total); // Ordenar por mayor uso

        res.status(200).json(reporteFinal);

    } catch (err) {
        console.error('Error al generar reporte de insumos teóricos:', err);
        res.status(500).json({ error: 'Error del servidor: ' + err.message });
    }
});

// [GET] /api/debug/hora - Para verificar qué hora tiene el servidor
// [GET] /api/debug/hora - Verificación de hora local
app.get('/api/debug/hora', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                NOW() as hora_servidor_utc,
                (NOW() AT TIME ZONE 'America/Hermosillo') as hora_hermosillo_correcta,
                (NOW() AT TIME ZONE 'America/Hermosillo')::date as fecha_hermosillo_correcta
        `);
        res.json(result.rows[0]);
    } catch (err) {
        res.json({ error: err.message });
    }
});

// ======================================================================
// INICIALIZACIÓN DEL SERVIDOR
// ======================================================================
app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});
