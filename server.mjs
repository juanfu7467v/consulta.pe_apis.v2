import express from "express";
import admin from "firebase-admin";
import dotenv from "dotenv";
import axios from "axios";
import cors from "cors";

dotenv.config();

const app = express();

// 🟢 MIDDLEWARE DE SEGURIDAD Y PARSEO
// Límite de tamaño para evitar ataques de desbordamiento en el body
app.use(express.json({ limit: '100kb' })); 
app.use(express.urlencoded({ extended: true, limit: '100kb' }));

// 🟢 Configuración de CORS
// Nota: Para máxima seguridad, en producción deberías cambiar origin: "*" 
// por el dominio específico de tu frontend (ej: "https://miweb.com").
const corsOptions = {
  origin: "*", 
  methods: "POST,OPTIONS", // Solo permitimos POST y OPTIONS (preflight)
  allowedHeaders: ["Content-Type", "x-api-key", "x-admin-key"],
  exposedHeaders: ["x-api-key", "x-admin-key"],
  credentials: true,
};
app.use(cors(corsOptions));

// --- VARIABLES DE ENTORNO PARA PROVEEDORES ---
const API_URL_RENIEC = process.env.API_URL_RENIEC;
const API_URL_TELEFONIA = process.env.API_URL_TELEFONIA;
const API_URL_SUNARP = process.env.API_URL_SUNARP;
const API_URL_SUNAT = "https://dniruc.apisperu.com/api/v1/ruc/"; 
const TOKEN_SUNAT = process.env.TOKEN_SUNAT; // 🔧 Token desde secrets
const API_URL_EMPRESAS = process.env.API_URL_EMPRESAS || "";
const API_URL_MATRIMONIOS = process.env.API_URL_MATRIMONIOS || "";
const API_URL_DNI_NOMBRES = process.env.API_URL_DNI_NOMBRES || "";
const API_URL_VENEZOLANOS = process.env.API_URL_VENEZOLANOS || "";
const API_URL_CEDULA = process.env.API_URL_CEDULA || "";
const LOG_GUARDADO_BASE_URL = process.env.LOG_GUARDADO_URL || "";

// -------------------- FIREBASE --------------------
const serviceAccount = {
  type: process.env.FIREBASE_TYPE,
  project_id: process.env.FIREBASE_PROJECT_ID,
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, "\n"),
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  client_id: process.env.FIREBASE_CLIENT_ID,
  auth_uri: process.env.FIREBASE_AUTH_URI,
  token_uri: process.env.FIREBASE_TOKEN_URI,
  auth_provider_x509_cert_url: process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL,
  client_x509_cert_url: process.env.FIREBASE_CLIENT_X509_CERT_URL,
  universe_domain: process.env.FIREBASE_UNIVERSE_DOMAIN,
};

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
}

const db = admin.firestore();

// -------------------- FUNCIONES DE LIMPIEZA DE RESPUESTAS --------------------

/**
 * 🔧 NUEVA FUNCIÓN: Formatear búsqueda de nombres para el endpoint de venezolanos
 * Convierte el texto ingresado al formato /nmv nombres|apellidopaterno|apellidomaterno
 */
const formatearBusquedaNombres = (query) => {
  if (!query || typeof query !== 'string') return '';
  
  // Limpiar espacios extras y convertir a mayúsculas
  const queryLimpio = query.trim().replace(/\s+/g, ' ').toUpperCase();
  const palabras = queryLimpio.split(' ');
  
  let nombres = '';
  let apellidoPaterno = '';
  let apellidoMaterno = '';
  
  if (palabras.length === 2) {
    // Caso: nombre apellido (solo un apellido)
    nombres = palabras[0];
    apellidoPaterno = palabras[1];
    apellidoMaterno = '';
  } else if (palabras.length >= 3) {
    // Caso: nombre1 nombre2 apellido1 apellido2
    // Los apellidos son las últimas dos palabras
    const apellidoMaternoIndex = palabras.length - 1;
    const apellidoPaternoIndex = palabras.length - 2;
    
    apellidoMaterno = palabras[apellidoMaternoIndex];
    apellidoPaterno = palabras[apellidoPaternoIndex];
    nombres = palabras.slice(0, apellidoPaternoIndex).join(',');
  } else {
    // Caso: un solo término
    nombres = palabras[0];
    apellidoPaterno = '';
    apellidoMaterno = '';
  }
  
  // Aplicar reglas de transformación
  // Si apellido paterno tiene más de 1 palabra, reemplazar espacios con '+'
  if (apellidoPaterno && apellidoPaterno.includes(' ')) {
    apellidoPaterno = apellidoPaterno.replace(/ /g, '+');
  }
  
  // Si apellido materno tiene más de 1 palabra, reemplazar espacios con '+'
  if (apellidoMaterno && apellidoMaterno.includes(' ')) {
    apellidoMaterno = apellidoMaterno.replace(/ /g, '+');
  }
  
  // Construir el formato /nmv nombres|apellidopaterno|apellidomaterno
  return `${nombres}|${apellidoPaterno}|${apellidoMaterno}`;
};

/**
 * 🔧 FUNCIÓN MEJORADA: Parsear múltiples resultados desde el texto
 */
const parsearBloqueResultado = (texto) => {
  if (!texto || typeof texto !== 'string') return null;
  
  const lineas = texto.split('\n').map(l => l.trim()).filter(l => l);
  const resultado = {};
  
  for (const linea of lineas) {
    // Buscar líneas con formato "CLAVE : VALOR"
    const match = linea.match(/^([A-ZÁÉÍÓÚÑa-záéíóúñ\s]+)\s*:\s*(.+)$/);
    if (match) {
      let clave = match[1].trim().toLowerCase();
      let valor = match[2].trim();
      
      // Normalizar claves comunes
      clave = clave
        .replace(/\s+/g, '_')
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, ""); // Eliminar tildes
      
      resultado[clave] = valor;
    }
  }
  
  return Object.keys(resultado).length > 0 ? resultado : null;
};

/**
 * 🔧 FUNCIÓN MEJORADA: Limpiar y transformar respuestas de APIs de DNI y Cédula
 * Ahora procesa correctamente múltiples resultados y los devuelve como array JSON
 */
const limpiarRespuestaEspecial = (data) => {
  if (!data || typeof data !== 'object') return data;
  
  // Si no tiene el campo "message" o "status", retornar sin procesar
  if (!data.message || data.status !== "success") {
    return data;
  }
  
  let mensaje = data.message;
  
  // 🔹 PASO 1: Eliminar información innecesaria
  // Eliminar todo desde "↞" hasta el final (incluyendo Credits, Wanted for, etc.)
  const indiceLimpieza = mensaje.indexOf("↞");
  if (indiceLimpieza !== -1) {
    mensaje = mensaje.substring(0, indiceLimpieza).trim();
  }
  
  // 🔹 PASO 2: Extraer el número total de resultados si existe
  const totalMatch = mensaje.match(/Se encontr[oó]\s*(\d+)\s*resultados?\.?/i);
  const totalResultados = totalMatch ? parseInt(totalMatch[1]) : null;
  
  // 🔹 PASO 3: Separar el mensaje en bloques por resultado
  // Patrón: DNI : XXXXXXXX - Y seguido de saltos de línea
  const bloques = mensaje.split(/(?=DNI\s*:\s*\d+\s*-\s*\d+)/g).filter(bloque => bloque.trim().length > 0);
  
  // 🔹 PASO 4: Procesar cada bloque y convertirlo en objeto JSON
  const resultados = [];
  for (const bloque of bloques) {
    const resultado = parsearBloqueResultado(bloque);
    if (resultado && Object.keys(resultado).length > 0) {
      resultados.push(resultado);
    }
  }
  
  // 🔹 PASO 5: Si no se encontraron resultados con el patrón, intentar procesar el mensaje completo
  if (resultados.length === 0 && mensaje.trim()) {
    const resultadoUnico = parsearBloqueResultado(mensaje);
    if (resultadoUnico) {
      resultados.push(resultadoUnico);
    }
  }
  
  // 🔹 PASO 6: Estructurar la respuesta final
  if (resultados.length > 0) {
    return {
      resultados,
      total_encontrados: resultados.length,
      mensaje_original: totalResultados ? `Se encontraron ${totalResultados} resultados` : undefined
    };
  }
  
  // Si no se pudo parsear nada, devolver los datos originales
  return data;
};

// -------------------- MIDDLEWARE DE AUTENTICACIÓN --------------------
const authMiddleware = async (req, res, next) => {
  if (req.method === 'OPTIONS') {
    return next();
  }
  
  // Verificamos que sea POST (Seguridad extra)
  if (req.method !== 'POST') {
     return res.status(405).json({ success: false, error: "Método no permitido. Solo se acepta POST." });
  }

  const token = req.headers["x-api-key"];
  if (!token) {
    return res.status(401).json({ success: false, error: "Falta el token de API (x-api-key)" });
  }

  try {
    const usersRef = db.collection("usuarios");
    const snapshot = await usersRef.where("apiKey", "==", token).get();
    if (snapshot.empty) {
      return res.status(403).json({ success: false, error: "Token inválido" });
    }

    const userDoc = snapshot.docs[0];
    const userData = userDoc.data();
    const userId = userDoc.id;
    
    const validPlans = ["creditos", "ilimitado"];
    
    if (!validPlans.includes(userData.tipoPlan)) {
      return res.status(403).json({ 
        success: false, 
        error: "Tu plan no es válido o está deshabilitado. Recarga o contacta a soporte.",
      });
    }

    if (userData.tipoPlan === "creditos") {
      if ((userData.creditos ?? 0) <= 0) {
        return res.status(402).json({
          success: false,
          error: "No te quedan créditos, recarga tu plan para seguir consultando",
        });
      }
    }

    if (userData.tipoPlan === "ilimitado") {
      const fechaActivacion = userData.fechaActivacion ? userData.fechaActivacion.toDate() : null;
      const duracion = userData.duracionDias || 0;

      if (fechaActivacion && duracion > 0) {
        const fechaFin = new Date(fechaActivacion);
        fechaFin.setDate(fechaFin.getDate() + duracion);

        const hoy = new Date();
        if (hoy > fechaFin) {
          return res.status(403).json({
            success: false,
            error: "Sorpresa, tu plan ilimitado ha vencido, renueva tu plan para seguir consultando",
          });
        }
      } else {
        return res.status(403).json({
          success: false,
          error: "Tu plan ilimitado no es válido, por favor contacta soporte",
        });
      }
    }

    req.user = { id: userId, ...userData };
    next();
  } catch (error) {
    console.error("Error en middleware:", error);
    res.status(500).json({ success: false, error: "Error interno al validar el token" });
  }
};

const creditosMiddleware = (costo) => {
  return async (req, res, next) => {
    if (req.method === 'OPTIONS') return next();
    
    const domain = req.headers.origin || req.headers.referer || "Unknown/Direct Access";
    
    if (req.user.tipoPlan === "creditos") {
      const currentCredits = req.user.creditos ?? 0;
      
      if (currentCredits < costo) {
        return res.status(402).json({
          success: false,
          error: `Créditos insuficientes (Se requerían ${costo} créditos). Saldo actual: ${currentCredits}`,
        });
      }
    }

    req.logData = {
      domain: domain,
      cost: req.user.tipoPlan === "creditos" ? costo : 0,
      endpoint: req.path,
    };
    
    next();
  };
};

// -------------------- FUNCIONES DE APOYO --------------------
const generateMetaData = () => {
  return {
    version: "3.0.0",
    timestamp: new Date().toISOString(),
    request_id: `req_${Math.random().toString(36).substring(2, 15)}`,
    server: "cluster-aws-pe-secure-01"
  };
};

const generateUserPlanData = (user) => {
  return {
    tipo: user.tipoPlan,
    creditosRestantes: user.tipoPlan === "creditos" ? (user.creditos ?? 0) : null,
  };
};

const deducirCreditosFirebase = async (req, costo) => {
  const userRef = db.collection("usuarios").doc(req.user.id);
  const currentTime = new Date();
  const domain = req.logData.domain;

  if (req.user.tipoPlan === "creditos" && costo > 0) {
    try {
      await db.runTransaction(async (t) => {
        const freshUserDoc = await t.get(userRef);
        const currentCredits = freshUserDoc.data().creditos ?? 0;
        
        if (currentCredits < costo) {
          throw new Error("Saldo insuficiente durante la deducción atómica");
        }
        
        t.update(userRef, {
          creditos: currentCredits - costo,
          ultimaConsulta: currentTime,
          ultimoDominio: domain,
        });
        
        req.user.creditos = currentCredits - costo;
      });
    } catch (e) {
      console.error("Error crítico al deducir créditos:", e.message);
    }
  } else if (req.user.tipoPlan === "ilimitado") {
    await userRef.update({
      ultimaConsulta: currentTime,
      ultimoDominio: domain,
    });
  }
};

const guardarLogExterno = async (logData) => {
  const horaConsulta = new Date(logData.timestamp).toISOString();
  const url = `${LOG_GUARDADO_BASE_URL}/log_consulta?host=${encodeURIComponent(logData.domain)}&hora=${encodeURIComponent(horaConsulta)}&endpoint=${encodeURIComponent(logData.endpoint)}&userId=${encodeURIComponent(logData.userId)}&costo=${logData.cost}`;
  
  try {
    await axios.get(url);
  } catch (e) {
    console.error("Error al guardar log en API externa:", e.message);
  }
};

const limpiarRespuestaProveedor = (data) => {
  if (!data || typeof data !== 'object') return data;
  
  const cleaned = { ...data };
  
  // CORRECCIÓN CRÍTICA: Uso de corchetes para propiedades con guiones
  delete cleaned["developed-by"]; 
  delete cleaned.credits;
  delete cleaned.bot_used;
  delete cleaned.bot;
  delete cleaned.chat_id;
  delete cleaned.watermark;
  delete cleaned.provider;
  
  // Limpiar mensajes de error genéricos
  if (cleaned.error && typeof cleaned.error === 'string') {
    if (cleaned.error.includes("Token con falta de pago") || 
        cleaned.error.includes("token expirado") ||
        cleaned.error.includes("insufficient credits")) {
      cleaned.error = "Error en la consulta, intenta nuevamente";
    }
  }
  
  return cleaned;
};

const formatoRespuestaEstandar = (success, data, user, metadata = null) => {
  const meta = metadata || generateMetaData();
  
  return {
    success,
    data: limpiarRespuestaProveedor(data),
    meta,
    "consulta-pe": {
      poweredBy: "Intermediario Consulta Pe v2",
      status: "Verified Source",
      userPlan: generateUserPlanData(user)
    },
    disclaimer: "Información obtenida de fuentes públicas. El uso de estos datos es responsabilidad exclusiva del cliente según Ley 29733."
  };
};

const consumirAPIProveedor = async (req, res, url, costo, aplicarLimpiezaEspecial = false) => {
  try {
    const response = await axios.get(url);
    
    if (response.status >= 200 && response.status < 300) {
      await deducirCreditosFirebase(req, costo);
      
      const logData = {
        userId: req.user.id,
        timestamp: new Date(),
        ...req.logData,
      };
      guardarLogExterno(logData);
      
      // 🔹 APLICAR LIMPIEZA ESPECIAL si está activada
      let dataFinal = response.data;
      if (aplicarLimpiezaEspecial) {
        dataFinal = limpiarRespuestaEspecial(response.data);
      }
      
      return res.json(formatoRespuestaEstandar(true, dataFinal, req.user));
    } else {
      return res.status(response.status).json(
        formatoRespuestaEstandar(false, response.data, req.user)
      );
    }
  } catch (error) {
    console.error("Error al consumir API:", error.message);
    
    const errorData = error.response ? error.response.data : { error: error.message };
    return res.status(error.response ? error.response.status : 500).json(
      formatoRespuestaEstandar(false, errorData, req.user)
    );
  }
};

// -------------------- RUTAS SEGURAS (SOLO POST) --------------------

// 1. RENIEC (7 créditos) -> /v3/consulta/dni
app.post("/v3/consulta/dni", authMiddleware, creditosMiddleware(7), async (req, res) => {
  const { dni } = req.body;
  if (!dni) {
    return res.status(400).json(formatoRespuestaEstandar(false, { error: "DNI requerido en el body" }, req.user));
  }
  await consumirAPIProveedor(req, res, `${API_URL_RENIEC}/reniec?dni=${dni}`, 7);
});

// 2. Telefonía por Documento (9 créditos) -> /v3/consulta/telefonia-doc
app.post("/v3/consulta/telefonia-doc", authMiddleware, creditosMiddleware(9), async (req, res) => {
  const { documento } = req.body;
  if (!documento) {
    return res.status(400).json(formatoRespuestaEstandar(false, { error: "Documento requerido en el body" }, req.user));
  }
  await consumirAPIProveedor(req, res, `${API_URL_TELEFONIA}/telefonia-doc?documento=${documento}`, 9);
});

// 3. Telefonía por Número de Teléfono (8 créditos) -> /v3/consulta/telefonia-num
app.post("/v3/consulta/telefonia-num", authMiddleware, creditosMiddleware(8), async (req, res) => {
  const { numero } = req.body;
  if (!numero) {
    return res.status(400).json(formatoRespuestaEstandar(false, { error: "Número requerido en el body" }, req.user));
  }
  await consumirAPIProveedor(req, res, `${API_URL_TELEFONIA}/telefonia-num?numero=${numero}`, 8);
});

// 4. Datos SUNARP (8 créditos) -> /v3/consulta/placa
app.post("/v3/consulta/placa", authMiddleware, creditosMiddleware(8), async (req, res) => {
  const { placa } = req.body;
  if (!placa) {
    return res.status(400).json(formatoRespuestaEstandar(false, { error: "Placa requerida en el body" }, req.user));
  }
  await consumirAPIProveedor(req, res, `${API_URL_SUNARP}/vehiculos?placa=${placa}`, 8);
});

// 5. SUNAT por RUC (6 créditos) -> /v3/consulta/ruc
// 🔧 CAMBIO REALIZADO: Ahora usa la nueva API de apisperu.com con token
app.post("/v3/consulta/ruc", authMiddleware, creditosMiddleware(6), async (req, res) => {
  const { data } = req.body;
  if (!data) {
    return res.status(400).json(formatoRespuestaEstandar(false, { error: "RUC requerido en el body" }, req.user));
  }
  
  // 🔧 Construir la URL con el formato de la nueva API: https://dniruc.apisperu.com/api/v1/ruc/{RUC}?token={TOKEN_SUNAT}
  const apiUrl = `${API_URL_SUNAT}${data}?token=${TOKEN_SUNAT}`;
  
  await consumirAPIProveedor(req, res, apiUrl, 6);
});

// 6. SUNAT por Razón Social (5 créditos) -> /v3/consulta/razon-social
// 🔧 CAMBIO REALIZADO: Para búsqueda por razón social, mantenemos el endpoint anterior ya que la nueva API no soporta este tipo de búsqueda
app.post("/v3/consulta/razon-social", authMiddleware, creditosMiddleware(5), async (req, res) => {
  const { data } = req.body;
  if (!data) {
    return res.status(400).json(formatoRespuestaEstandar(false, { error: "Razón social requerida en el body" }, req.user));
  }
  
  // Para búsqueda por razón social, mantenemos el proveedor anterior
  const API_URL_SUNAT_RAZON = process.env.API_URL_SUNAT_RAZON || "https://banckend-poxyv1-cosultape-masitaprex.fly.dev";
  await consumirAPIProveedor(req, res, `${API_URL_SUNAT_RAZON}/sunat-razon?data=${data}`, 5);
});

// 7. Empresas donde figura (4 créditos) -> /v3/consulta/empresas
app.post("/v3/consulta/empresas", authMiddleware, creditosMiddleware(4), async (req, res) => {
  const { dni } = req.body;
  if (!dni) {
    return res.status(400).json(formatoRespuestaEstandar(false, { error: "DNI requerido en el body" }, req.user));
  }
  await consumirAPIProveedor(req, res, `${API_URL_EMPRESAS}/empresas?dni=${dni}`, 4);
});

// 8. Matrimonios Registrados (6 créditos) -> /v3/consulta/matrimonios
app.post("/v3/consulta/matrimonios", authMiddleware, creditosMiddleware(6), async (req, res) => {
  const { dni } = req.body;
  if (!dni) {
    return res.status(400).json(formatoRespuestaEstandar(false, { error: "DNI requerido en el body" }, req.user));
  }
  await consumirAPIProveedor(req, res, `${API_URL_MATRIMONIOS}/matrimonios?dni=${dni}`, 6);
});

// 🔹 9. BUSCAR DNI POR NOMBRES (5 créditos) -> /v3/consulta/buscar-dni
// ✅ CON LIMPIEZA ESPECIAL ACTIVADA
app.post("/v3/consulta/buscar-dni", authMiddleware, creditosMiddleware(5), async (req, res) => {
  const { nombres, apepaterno, apematerno } = req.body;
  if (!nombres || !apepaterno || !apematerno) {
    return res.status(400).json(formatoRespuestaEstandar(false, { error: "Nombres y apellidos requeridos en el body" }, req.user));
  }
  await consumirAPIProveedor(req, res, `${API_URL_DNI_NOMBRES}/dni_nombres?nombres=${nombres}&apepaterno=${apepaterno}&apematerno=${apematerno}`, 5, true);
});

// 🔹 10. BUSCAR CÉDULA POR NOMBRES (5 créditos) -> /v3/consulta/buscar-cedula
// ✅ CORREGIDO: Ahora usa el formato /nmv correctamente
app.post("/v3/consulta/buscar-cedula", authMiddleware, creditosMiddleware(5), async (req, res) => {
  const { query } = req.body;
  if (!query) {
    return res.status(400).json(formatoRespuestaEstandar(false, { error: "Query requerido en el body" }, req.user));
  }
  
  // 🔧 Transformar el query al formato nmv correcto
  const queryFormateado = formatearBusquedaNombres(query);
  
  // 🔧 Construir la URL con el formato correcto /nmv
  const apiUrl = `${API_URL_VENEZOLANOS}/nmv ${encodeURIComponent(queryFormateado)}`;
  
  await consumirAPIProveedor(req, res, apiUrl, 5, true);
});

// 🔹 11. CONSULTAR CÉDULA (5 créditos) -> /v3/consulta/cedula
// ✅ CON LIMPIEZA ESPECIAL ACTIVADA
app.post("/v3/consulta/cedula", authMiddleware, creditosMiddleware(5), async (req, res) => {
  const { cedula } = req.body;
  if (!cedula) {
    return res.status(400).json(formatoRespuestaEstandar(false, { error: "Cédula requerida en el body" }, req.user));
  }
  await consumirAPIProveedor(req, res, `${API_URL_CEDULA}/cedula?cedula=${cedula}`, 5, true);
});

// -------------------- ENDPOINT RAIZ (HEALTH CHECK) --------------------
app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "🚀 API Consulta PE Segura v3.0.0 funcionando",
    meta: generateMetaData(),
    security: {
      mode: "Strict POST",
      encryption: "TLS/SSL Enforced via Edge"
    }
  });
});

// -------------------- SERVER --------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Servidor Seguro corriendo en http://0.0.0.0:${PORT}`);
});
