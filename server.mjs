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
const API_URL_RENIEC = process.env.API_URL_RENIEC || "https://banckend-poxyv1-cosultape-masitaprex.fly.dev";
const API_URL_TELEFONIA = process.env.API_URL_TELEFONIA || "https://banckend-poxyv1-cosultape-masitaprex.fly.dev";
const API_URL_SUNARP = process.env.API_URL_SUNARP || "https://banckend-poxyv1-cosultape-masitaprex.fly.dev";
const API_URL_SUNAT = process.env.API_URL_SUNAT || "https://banckend-poxyv1-cosultape-masitaprex.fly.dev";
const API_URL_EMPRESAS = process.env.API_URL_EMPRESAS || "https://banckend-poxyv1-cosultape-masitaprex.fly.dev";
const API_URL_MATRIMONIOS = process.env.API_URL_MATRIMONIOS || "https://banckend-poxyv1-cosultape-masitaprex.fly.dev";
const API_URL_DNI_NOMBRES = process.env.API_URL_DNI_NOMBRES || "https://bankend-tlgm.fly.dev";
const API_URL_VENEZOLANOS = process.env.API_URL_VENEZOLANOS || "https://bankend-tlgm.fly.dev";
const API_URL_CEDULA = process.env.API_URL_CEDULA || "https://bankend-tlgm-2p.fly.dev";
const LOG_GUARDADO_BASE_URL = process.env.LOG_GUARDADO_URL || "https://base-datos-consulta-pe.fly.dev/guardar";

// -------------------- FUNCIONES DE PROCESAMIENTO DE RESPUESTAS --------------------
/**
 * Función para limpiar y estructurar las respuestas de las APIs especiales
 * @param {string} data - Respuesta cruda de la API
 * @param {string} endpointType - Tipo de endpoint para procesamiento específico
 * @returns {Array|Object} Datos estructurados en JSON
 */
const procesarRespuestaEspecial = (data, endpointType) => {
  try {
    // Si ya es un objeto JSON, limpiarlo si es necesario
    if (typeof data === 'object') {
      return limpiarRespuestaProveedor(data);
    }
    
    // Si es string, procesar según el formato específico
    if (typeof data === 'string') {
      // Para mensajes que contienen la estructura específica con "Se encontro X resultado"
      if (data.includes("Se encontro") && data.includes("DNI :")) {
        return procesarRespuestaDNI(data);
      }
      
      // Para respuestas de venezolanos
      if (data.includes("VENEZOLANOS") || endpointType === 'venezolanos') {
        return procesarRespuestaVenezolanos(data);
      }
      
      // Para respuestas de cédula
      if (data.includes("CÉDULA") || endpointType === 'cedula') {
        return procesarRespuestaCedula(data);
      }
    }
    
    return data;
  } catch (error) {
    console.error("Error procesando respuesta especial:", error);
    return data; // Devolver original si hay error
  }
};

/**
 * Procesa respuestas de DNI por nombres (formato específico)
 * @param {string} texto - Texto crudo de la respuesta
 * @returns {Array} Array de objetos JSON estructurados
 */
const procesarRespuestaDNI = (texto) => {
  // Eliminar la parte innecesaria desde "↞ Puedes visualizar"
  const partes = texto.split("↞ Puedes visualizar");
  const parteUtil = partes[0].trim();
  
  // Extraer el número de resultados
  const matchResultados = parteUtil.match(/Se encontro (\d+) resultado/);
  const numResultados = matchResultados ? parseInt(matchResultados[1]) : 0;
  
  if (numResultados === 0) {
    return [];
  }
  
  // Separar por bloques de datos (cada bloque empieza con "DNI :")
  const bloquesTexto = parteUtil.split(/\nDNI :/).filter(bloque => bloque.trim() !== '');
  
  const resultados = [];
  
  for (let i = 0; i < bloquesTexto.length; i++) {
    let bloque = bloquesTexto[i];
    if (i === 0) {
      // El primer bloque tiene el texto "Se encontro X resultado." antes del primer DNI
      bloque = bloque.replace(/Se encontro \d+ resultado\.?\n?/, '');
    }
    
    // Reconstruir la línea DNI
    bloque = `DNI :${bloque}`;
    
    const lineas = bloque.split('\n').filter(linea => linea.trim() !== '');
    const persona = {};
    
    for (const linea of lineas) {
      if (linea.includes(' : ')) {
        const [clave, ...valorPartes] = linea.split(' : ');
        const valor = valorPartes.join(' : ').trim();
        
        // Convertir claves a formato JSON estándar
        let claveJson = clave.trim().toLowerCase();
        if (claveJson === 'dni') {
          persona['dni'] = valor;
        } else if (claveJson === 'apellidos') {
          persona['apellidos'] = valor;
        } else if (claveJson === 'nombres') {
          persona['nombres'] = valor;
        } else if (claveJson === 'edad') {
          persona['edad'] = valor;
        } else {
          // Para otras claves, usar nombre en minúsculas sin espacios
          persona[claveJson.replace(/\s+/g, '_')] = valor;
        }
      }
    }
    
    if (Object.keys(persona).length > 0) {
      resultados.push(persona);
    }
  }
  
  return resultados.length === 1 ? resultados[0] : resultados;
};

/**
 * Procesa respuestas de venezolanos por nombres
 * @param {string} texto - Texto crudo de la respuesta
 * @returns {Array} Array de objetos JSON estructurados
 */
const procesarRespuestaVenezolanos = (texto) => {
  // Eliminar partes innecesarias similares
  const partes = texto.split(/↞ Puedes visualizar|Credits :|Wanted for :/);
  const parteUtil = partes[0].trim();
  
  // Buscar patrones de datos
  const lineas = parteUtil.split('\n').filter(linea => linea.trim() !== '');
  const resultados = [];
  let personaActual = {};
  
  for (const linea of lineas) {
    if (linea.includes(' : ')) {
      const [clave, ...valorPartes] = linea.split(' : ');
      const valor = valorPartes.join(' : ').trim();
      const claveJson = clave.trim().toLowerCase();
      
      personaActual[claveJson.replace(/\s+/g, '_')] = valor;
    } else if (Object.keys(personaActual).length > 0 && linea.trim()) {
      // Si la línea no tiene ":" pero ya tenemos datos, podría ser el inicio de una nueva persona
      resultados.push(personaActual);
      personaActual = {};
    }
  }
  
  // Agregar la última persona si existe
  if (Object.keys(personaActual).length > 0) {
    resultados.push(personaActual);
  }
  
  return resultados.length === 1 ? resultados[0] : resultados;
};

/**
 * Procesa respuestas de cédula venezolana
 * @param {string} texto - Texto crudo de la respuesta
 * @returns {Object} Objeto JSON estructurado
 */
const procesarRespuestaCedula = (texto) => {
  // Eliminar partes innecesarias
  const partes = texto.split(/↞ Puedes visualizar|Credits :|Wanted for :/);
  const parteUtil = partes[0].trim();
  
  const lineas = parteUtil.split('\n').filter(linea => linea.trim() !== '');
  const resultado = {};
  
  for (const linea of lineas) {
    if (linea.includes(' : ')) {
      const [clave, ...valorPartes] = linea.split(' : ');
      const valor = valorPartes.join(' : ').trim();
      const claveJson = clave.trim().toLowerCase().replace(/\s+/g, '_');
      
      resultado[claveJson] = valor;
    }
  }
  
  return resultado;
};

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
    version: "3.0.0", // Actualizado a v3
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
  // Nota: Incluso si guardamos el log por GET, tus endpoints principales ahora son solo POST.
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

// MODIFICACIÓN: Función mejorada para consumir API con procesamiento especial
const consumirAPIProveedor = async (req, res, url, costo, endpointType = null) => {
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
      
      // MODIFICACIÓN: Procesar respuesta si es de los endpoints especiales
      let datosProcesados = response.data;
      
      // Solo procesar si es de los endpoints que necesitan transformación
      if (endpointType || 
          url.includes('/dni_nombres') || 
          url.includes('/venezolanos_nombres') || 
          url.includes('/cedula')) {
        
        // Determinar el tipo de endpoint si no se especificó
        const tipo = endpointType || 
                    (url.includes('/dni_nombres') ? 'dni_nombres' : 
                     url.includes('/venezolanos_nombres') ? 'venezolanos' : 
                     url.includes('/cedula') ? 'cedula' : null);
        
        datosProcesados = procesarRespuestaEspecial(response.data, tipo);
      }
      
      return res.json(formatoRespuestaEstandar(true, datosProcesados, req.user));
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
// AHORA TODAS BAJO EL PREFIJO /v3/consulta/

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
app.post("/v3/consulta/ruc", authMiddleware, creditosMiddleware(6), async (req, res) => {
  const { data } = req.body;
  if (!data) {
    return res.status(400).json(formatoRespuestaEstandar(false, { error: "RUC requerido en el body" }, req.user));
  }
  await consumirAPIProveedor(req, res, `${API_URL_SUNAT}/sunat?data=${data}`, 6);
});

// 6. SUNAT por Razón Social (5 créditos) -> /v3/consulta/razon-social
app.post("/v3/consulta/razon-social", authMiddleware, creditosMiddleware(5), async (req, res) => {
  const { data } = req.body;
  if (!data) {
    return res.status(400).json(formatoRespuestaEstandar(false, { error: "Razón social requerida en el body" }, req.user));
  }
  await consumirAPIProveedor(req, res, `${API_URL_SUNAT}/sunat-razon?data=${data}`, 5);
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

// 9. BUSCAR DNI POR NOMBRES (5 créditos) -> /v3/consulta/buscar-dni
app.post("/v3/consulta/buscar-dni", authMiddleware, creditosMiddleware(5), async (req, res) => {
  const { nombres, apepaterno, apematerno } = req.body;
  if (!nombres || !apepaterno || !apematerno) {
    return res.status(400).json(formatoRespuestaEstandar(false, { error: "Nombres y apellidos requeridos en el body" }, req.user));
  }
  await consumirAPIProveedor(req, res, `${API_URL_DNI_NOMBRES}/dni_nombres?nombres=${nombres}&apepaterno=${apepaterno}&apematerno=${apematerno}`, 5, 'dni_nombres');
});

// 10. BUSCAR CÉDULA POR NOMBRES (5 créditos) -> /v3/consulta/buscar-cedula
app.post("/v3/consulta/buscar-cedula", authMiddleware, creditosMiddleware(5), async (req, res) => {
  const { query } = req.body;
  if (!query) {
    return res.status(400).json(formatoRespuestaEstandar(false, { error: "Query requerido en el body" }, req.user));
  }
  await consumirAPIProveedor(req, res, `${API_URL_VENEZOLANOS}/venezolanos_nombres?query=${encodeURIComponent(query)}`, 5, 'venezolanos');
});

// 11. CONSULTAR CÉDULA (5 créditos) -> /v3/consulta/cedula
app.post("/v3/consulta/cedula", authMiddleware, creditosMiddleware(5), async (req, res) => {
  const { cedula } = req.body;
  if (!cedula) {
    return res.status(400).json(formatoRespuestaEstandar(false, { error: "Cédula requerida en el body" }, req.user));
  }
  await consumirAPIProveedor(req, res, `${API_URL_CEDULA}/cedula?cedula=${cedula}`, 5, 'cedula');
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
