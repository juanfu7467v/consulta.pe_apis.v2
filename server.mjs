import express from "express";
import admin from "firebase-admin";
import dotenv from "dotenv";
import axios from "axios";
import cors from "cors";

dotenv.config();

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 🟢 Configuración de CORS
const corsOptions = {
  origin: "*",
  methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
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

// -------------------- HELPER DE PARÁMETROS --------------------
const getQueryParams = (req) => {
  return req.method === 'GET' ? req.query : req.body;
};

// -------------------- MIDDLEWARE --------------------
const authMiddleware = async (req, res, next) => {
  if (req.method === 'OPTIONS') {
    return next();
  }
  
  const token = req.headers["x-api-key"];
  if (!token) {
    return res.status(401).json({ success: false, error: "Falta el token de API" });
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
    if (req.method === 'OPTIONS') {
      return next();
    }
    
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
    version: "2.0.4",
    timestamp: new Date().toISOString(),
    request_id: `req_${Math.random().toString(36).substring(2, 15)}`,
    server: "cluster-aws-pe-01"
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
  
  // Eliminar campos comunes de proveedores
  delete cleaned.developed-by;
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

const consumirAPIProveedor = async (req, res, url, costo) => {
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
      
      return res.json(formatoRespuestaEstandar(true, response.data, req.user));
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

// -------------------- NUEVAS RUTAS (11 APIs) --------------------

// 1. RENIEC (7 créditos)
app.post("/api/reniec", authMiddleware, creditosMiddleware(7), async (req, res) => {
  const { dni } = getQueryParams(req);
  if (!dni) {
    return res.status(400).json(formatoRespuestaEstandar(false, { error: "DNI requerido" }, req.user));
  }
  await consumirAPIProveedor(req, res, `${API_URL_RENIEC}/reniec?dni=${dni}`, 7);
});

// 2. Telefonía por Documento (9 créditos)
app.post("/api/telefonia-doc", authMiddleware, creditosMiddleware(9), async (req, res) => {
  const { documento } = getQueryParams(req);
  if (!documento) {
    return res.status(400).json(formatoRespuestaEstandar(false, { error: "Documento requerido" }, req.user));
  }
  await consumirAPIProveedor(req, res, `${API_URL_TELEFONIA}/telefonia-doc?documento=${documento}`, 9);
});

// 3. Telefonía por Número de Teléfono (8 créditos)
app.post("/api/telefonia-num", authMiddleware, creditosMiddleware(8), async (req, res) => {
  const { numero } = getQueryParams(req);
  if (!numero) {
    return res.status(400).json(formatoRespuestaEstandar(false, { error: "Número requerido" }, req.user));
  }
  await consumirAPIProveedor(req, res, `${API_URL_TELEFONIA}/telefonia-num?numero=${numero}`, 8);
});

// 4. Datos SUNARP PROPIETARIO/VEHÍCULO (8 créditos)
app.post("/api/vehiculos", authMiddleware, creditosMiddleware(8), async (req, res) => {
  const { placa } = getQueryParams(req);
  if (!placa) {
    return res.status(400).json(formatoRespuestaEstandar(false, { error: "Placa requerida" }, req.user));
  }
  await consumirAPIProveedor(req, res, `${API_URL_SUNARP}/vehiculos?placa=${placa}`, 8);
});

// 5. SUNAT por RUC (6 créditos)
app.post("/api/sunat", authMiddleware, creditosMiddleware(6), async (req, res) => {
  const { data } = getQueryParams(req);
  if (!data) {
    return res.status(400).json(formatoRespuestaEstandar(false, { error: "RUC requerido" }, req.user));
  }
  await consumirAPIProveedor(req, res, `${API_URL_SUNAT}/sunat?data=${data}`, 6);
});

// 6. SUNAT por Razón Social (5 créditos)
app.post("/api/sunat-razon", authMiddleware, creditosMiddleware(5), async (req, res) => {
  const { data } = getQueryParams(req);
  if (!data) {
    return res.status(400).json(formatoRespuestaEstandar(false, { error: "Razón social requerida" }, req.user));
  }
  await consumirAPIProveedor(req, res, `${API_URL_SUNAT}/sunat-razon?data=${data}`, 5);
});

// 7. Empresas donde figura (4 créditos)
app.post("/api/empresas", authMiddleware, creditosMiddleware(4), async (req, res) => {
  const { dni } = getQueryParams(req);
  if (!dni) {
    return res.status(400).json(formatoRespuestaEstandar(false, { error: "DNI requerido" }, req.user));
  }
  await consumirAPIProveedor(req, res, `${API_URL_EMPRESAS}/empresas?dni=${dni}`, 4);
});

// 8. Matrimonios Registrados (6 créditos)
app.post("/api/matrimonios", authMiddleware, creditosMiddleware(6), async (req, res) => {
  const { dni } = getQueryParams(req);
  if (!dni) {
    return res.status(400).json(formatoRespuestaEstandar(false, { error: "DNI requerido" }, req.user));
  }
  await consumirAPIProveedor(req, res, `${API_URL_MATRIMONIOS}/matrimonios?dni=${dni}`, 6);
});

// 9. BUSCAR DNI POR NOMBRES Y APELLIDOS (5 créditos)
app.post("/api/dni_nombres", authMiddleware, creditosMiddleware(5), async (req, res) => {
  const { nombres, apepaterno, apematerno } = getQueryParams(req);
  if (!nombres || !apepaterno || !apematerno) {
    return res.status(400).json(formatoRespuestaEstandar(false, { error: "Nombres y apellidos requeridos" }, req.user));
  }
  await consumirAPIProveedor(req, res, `${API_URL_DNI_NOMBRES}/dni_nombres?nombres=${nombres}&apepaterno=${apepaterno}&apematerno=${apematerno}`, 5);
});

// 10. BUSCAR CÉDULA POR NOMBRES Y APELLIDOS (5 créditos)
app.post("/api/venezolanos_nombres", authMiddleware, creditosMiddleware(5), async (req, res) => {
  const { query } = getQueryParams(req);
  if (!query) {
    return res.status(400).json(formatoRespuestaEstandar(false, { error: "Query requerido" }, req.user));
  }
  await consumirAPIProveedor(req, res, `${API_URL_VENEZOLANOS}/venezolanos_nombres?query=${encodeURIComponent(query)}`, 5);
});

// 11. CONSULTAR CÉDULA (5 créditos)
app.post("/api/cedula", authMiddleware, creditosMiddleware(5), async (req, res) => {
  const { cedula } = getQueryParams(req);
  if (!cedula) {
    return res.status(400).json(formatoRespuestaEstandar(false, { error: "Cédula requerida" }, req.user));
  }
  await consumirAPIProveedor(req, res, `${API_URL_CEDULA}/cedula?cedula=${cedula}`, 5);
});

// -------------------- ENDPOINT RAIZ --------------------
app.use("/", (req, res) => {
  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }
  
  res.json({
    success: true,
    message: "🚀 API Consulta PE funcionando correctamente",
    meta: generateMetaData(),
    "consulta-pe": {
      poweredBy: "Intermediario Consulta Pe v2",
      status: "Operational",
      endpoints: 11
    }
  });
});

// -------------------- SERVER --------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});
