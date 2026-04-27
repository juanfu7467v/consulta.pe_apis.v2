import express from "express";
import admin from "firebase-admin";
import dotenv from "dotenv";
import axios from "axios";
import cors from "cors";
import { google } from "googleapis";

dotenv.config();

const app = express();
app.set("trust proxy", true);

// 🟢 MIDDLEWARE DE SEGURIDAD Y PARSEO
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: true, limit: "100kb" }));

// 🟢 Configuración de CORS
const corsOptions = {
  origin: "*",
  methods: "POST,OPTIONS",
  allowedHeaders: ["Content-Type", "x-api-key", "x-admin-key"],
  exposedHeaders: ["x-api-key", "x-admin-key"],
  credentials: true,
};
app.use(cors(corsOptions));

// -----------------------------------------------------------------------------
// VARIABLES DE ENTORNO PARA PROVEEDORES
// -----------------------------------------------------------------------------
const API_URL_RENIEC = process.env.API_URL_RENIEC || "";
const API_URL_TELEFONIA = process.env.API_URL_TELEFONIA || "";
const API_URL_SUNARP = process.env.API_URL_SUNARP || "";
const API_URL_SUNAT = "https://dniruc.apisperu.com/api/v1/ruc/";
const TOKEN_SUNAT = process.env.TOKEN_SUNAT || "";
const API_URL_EMPRESAS = process.env.API_URL_EMPRESAS || "";
const API_URL_MATRIMONIOS = process.env.API_URL_MATRIMONIOS || "";
const API_URL_DNI_NOMBRES = process.env.API_URL_DNI_NOMBRES || "";
const API_URL_VENEZOLANOS = process.env.API_URL_VENEZOLANOS || "";
const API_URL_CEDULA = process.env.API_URL_CEDULA || "";
const LOG_GUARDADO_BASE_URL = process.env.LOG_GUARDADO_URL || "";

// -----------------------------------------------------------------------------
// FIREBASE
// -----------------------------------------------------------------------------
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

// -----------------------------------------------------------------------------
// GOOGLE SHEETS AUDITORÍA ASÍNCRONA
// -----------------------------------------------------------------------------
const GOOGLE_SHEETS_SCOPES = [
  "https://www.googleapis.com/auth/spreadsheets",
];

const GOOGLE_SHEET_SPREADSHEET_ID =
  process.env.ID_DE_HOJA_CALCULO_GOOGLE_SHET || "";

const googleSheetsServiceAccount = {
  type: process.env.TYPE_GOOGLE_SHET,
  project_id: process.env.PROJECT_ID_GOOGLE_SHET,
  private_key_id: process.env.PRIVATE_KEY_ID_GOOGLE_SHET,
  private_key: process.env.PRIVATE_KEY_GOOGLE_SHET?.replace(/\\n/g, "\n"),
  client_email: process.env.CLIENT_EMAIL_GOOGLE_SHET,
  client_id: process.env.CLIENT_ID_GOOGLE_SHET,
  auth_uri: process.env.AUTH_URI_GOOGLE_SHET,
  token_uri: process.env.TOKEN_URI_GOOGLE_SHET,
  auth_provider_x509_cert_url:
    process.env.AUTH_PROVIDER_X509_CERT_URL_GOOGLE_SHET,
  client_x509_cert_url: process.env.CLIENT_X509_CERT_URL_GOOGLE_SHET,
  universe_domain: process.env.UNIVERSE_DOMAIN_GOOGLE_SHET,
};

const AUDIT_GOOGLE_SHEETS_ENABLED = Boolean(
  GOOGLE_SHEET_SPREADSHEET_ID &&
    googleSheetsServiceAccount.client_email &&
    googleSheetsServiceAccount.private_key
);

let googleSheetsClientPromise = null;
let auditSheetTitlePromise = null;
let auditQueue = Promise.resolve();

const getGoogleSheetsClient = async () => {
  if (!AUDIT_GOOGLE_SHEETS_ENABLED) {
    throw new Error(
      "Auditoría en Google Sheets deshabilitada: faltan secrets requeridos."
    );
  }

  if (!googleSheetsClientPromise) {
    googleSheetsClientPromise = (async () => {
      const auth = new google.auth.GoogleAuth({
        credentials: googleSheetsServiceAccount,
        scopes: GOOGLE_SHEETS_SCOPES,
      });

      return google.sheets({
        version: "v4",
        auth,
      });
    })();
  }

  return googleSheetsClientPromise;
};

const getAuditSheetTitle = async () => {
  if (!auditSheetTitlePromise) {
    auditSheetTitlePromise = (async () => {
      const sheets = await getGoogleSheetsClient();

      const spreadsheet = await sheets.spreadsheets.get({
        spreadsheetId: GOOGLE_SHEET_SPREADSHEET_ID,
        fields: "sheets(properties(title,index))",
      });

      const firstSheetTitle = spreadsheet?.data?.sheets?.[0]?.properties?.title;

      if (!firstSheetTitle) {
        throw new Error(
          "No se pudo determinar la primera pestaña del Google Sheet."
        );
      }

      return firstSheetTitle;
    })();
  }

  return auditSheetTitlePromise;
};

const formatAuditTimestamp = (date = new Date()) => {
  const formatter = new Intl.DateTimeFormat("sv-SE", {
    timeZone: "America/Lima",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });

  const parts = formatter.formatToParts(date);
  const map = Object.fromEntries(parts.map((p) => [p.type, p.value]));

  return `${map.year}-${map.month}-${map.day} ${map.hour}:${map.minute}:${map.second}`;
};

const obtenerIpOrigen = (req) => {
  const forwarded = req.headers["x-forwarded-for"];
  const realIp = req.headers["x-real-ip"];
  const cfIp = req.headers["cf-connecting-ip"];
  const rawIp =
    (typeof forwarded === "string" ? forwarded.split(",")[0].trim() : "") ||
    realIp ||
    cfIp ||
    req.ip ||
    req.socket?.remoteAddress ||
    "0.0.0.0";

  return String(rawIp).replace(/^::ffff:/, "");
};

const obtenerTipoConsultaDesdeRuta = (ruta = "") => {
  const path = String(ruta).split("?")[0];

  const mapa = {
    "/v3/consulta/dni": "RENIEC",
    "/v3/consulta/telefonia-doc": "TELEFONIA",
    "/v3/consulta/telefonia-num": "TELEFONIA",
    "/v3/consulta/placa": "SUNARP",
    "/v3/consulta/ruc": "SUNAT",
    "/v3/consulta/razon-social": "SUNAT",
    "/v3/consulta/empresas": "EMPRESAS",
    "/v3/consulta/matrimonios": "MATRIMONIOS",
    "/v3/consulta/buscar-dni": "RENIEC",
    "/v3/consulta/buscar-cedula": "CEDULA",
    "/v3/consulta/cedula": "CEDULA",
  };

  return mapa[path] || path || "DESCONOCIDO";
};

const obtenerInputConsultadoDesdeRequest = (req) => {
  const path = String(req.originalUrl || "").split("?")[0];

  switch (path) {
    case "/v3/consulta/dni":
      return req.body?.dni ?? "";
    case "/v3/consulta/telefonia-doc":
      return req.body?.documento ?? "";
    case "/v3/consulta/telefonia-num":
      return req.body?.numero ?? "";
    case "/v3/consulta/placa":
      return req.body?.placa ?? "";
    case "/v3/consulta/ruc":
      return req.body?.data ?? "";
    case "/v3/consulta/razon-social":
      return req.body?.data ?? "";
    case "/v3/consulta/empresas":
      return req.body?.dni ?? "";
    case "/v3/consulta/matrimonios":
      return req.body?.dni ?? "";
    case "/v3/consulta/buscar-dni":
      return [req.body?.nombres, req.body?.apepaterno, req.body?.apematerno]
        .filter(Boolean)
        .join(" ");
    case "/v3/consulta/buscar-cedula":
      return req.body?.query ?? "";
    case "/v3/consulta/cedula":
      return req.body?.cedula ?? "";
    default:
      return "";
  }
};

const determinarStatusRespuesta = ({
  success,
  data,
  httpStatus,
  statusOverride,
}) => {
  if (statusOverride) return statusOverride;

  if (httpStatus === 404) return "NO_RESULTS";
  if (success === false) return "ERROR";

  if (data == null) return "NO_RESULTS";
  if (Array.isArray(data) && data.length === 0) return "NO_RESULTS";
  if (
    typeof data === "object" &&
    Array.isArray(data.resultados) &&
    data.resultados.length === 0
  ) {
    return "NO_RESULTS";
  }

  const serialized = JSON.stringify(data || {}).toLowerCase();

  if (
    serialized.includes("no_results") ||
    serialized.includes("no results") ||
    serialized.includes("sin resultados") ||
    serialized.includes("no se encontraron") ||
    serialized.includes("not found") ||
    serialized.includes("no encontrado")
  ) {
    return "NO_RESULTS";
  }

  return "SUCCESS";
};

const appendAuditRowToGoogleSheets = async (auditRecord) => {
  const sheets = await getGoogleSheetsClient();
  const sheetTitle = await getAuditSheetTitle();

  const values = [
    [
      auditRecord.timestamp,
      auditRecord.idUsuario,
      auditRecord.tipoConsulta,
      auditRecord.inputConsultado,
      auditRecord.ipOrigen,
      auditRecord.statusRespuesta,
      auditRecord.requestId,
    ],
  ];

  await sheets.spreadsheets.values.append({
    spreadsheetId: GOOGLE_SHEET_SPREADSHEET_ID,
    range: `${sheetTitle}!A:G`,
    valueInputOption: "RAW",
    insertDataOption: "INSERT_ROWS",
    requestBody: {
      values,
    },
  });
};

const registrarAuditoriaAsync = (auditRecord) => {
  if (!AUDIT_GOOGLE_SHEETS_ENABLED) {
    console.warn(
      "[AUDITORIA] Google Sheets deshabilitado. Verifica tus secrets."
    );
    return;
  }

  auditQueue = auditQueue
    .then(() => appendAuditRowToGoogleSheets(auditRecord))
    .catch((error) => {
      console.error(
        "[AUDITORIA] Error al escribir en Google Sheets:",
        error?.response?.data || error.message || error
      );
    });
};

const registrarAuditoriaDeConsulta = (req, meta, success, data, httpStatus, statusOverride = null) => {
  const auditRecord = {
    timestamp: formatAuditTimestamp(new Date(meta.timestamp)),
    idUsuario: req.user?.apiKey || req.headers["x-api-key"] || req.user?.id || "",
    tipoConsulta: obtenerTipoConsultaDesdeRuta(req.originalUrl),
    inputConsultado: obtenerInputConsultadoDesdeRequest(req),
    ipOrigen: obtenerIpOrigen(req),
    statusRespuesta: determinarStatusRespuesta({
      success,
      data,
      httpStatus,
      statusOverride,
    }),
    requestId: meta.request_id,
  };

  // 🔥 Importante:
  // Solo guardamos metadata de auditoría.
  // NO se almacena el resultado sensible del proveedor.
  registrarAuditoriaAsync(auditRecord);
};

// -----------------------------------------------------------------------------
// FUNCIONES DE LIMPIEZA DE RESPUESTAS
// -----------------------------------------------------------------------------
const limpiarRespuestaEspecial = (data) => {
  if (!data || typeof data !== "object") return data;

  if (!data.message || data.status !== "success") {
    return data;
  }

  let mensaje = data.message;

  const indiceLimpieza = mensaje.indexOf("↞");
  if (indiceLimpieza !== -1) {
    mensaje = mensaje.substring(0, indiceLimpieza).trim();
  }

  const resultadosCompletos = mensaje;
  const bloques = resultadosCompletos
    .split(/(?=DNI\s:\s\d+\s-\s\d+)/g)
    .filter((bloque) => bloque.trim().length > 0);

  const resultados = [];

  for (const bloque of bloques) {
    const persona = parsearBloquePersona(bloque);
    if (persona && Object.keys(persona).length > 0) {
      resultados.push(persona);
    }
  }

  if (resultados.length === 0) {
    const personaUnica = parsearBloquePersona(mensaje);
    if (personaUnica && Object.keys(personaUnica).length > 0) {
      return { resultados: [personaUnica] };
    }
    return data;
  }

  return {
    resultados,
    total_encontrado: resultados.length,
    mensaje_original: `Se encontraron ${resultados.length} resultados`,
  };
};

const parsearBloquePersona = (texto) => {
  if (!texto || typeof texto !== "string") return null;

  const lineas = texto
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && l.length > 0);

  const persona = {};

  const mapeoClaves = {
    dni: "dni",
    cedula: "dni",
    apellidos: "apellidos",
    nombres: "nombres",
    nombre: "nombres",
    edad: "edad",
    fecha_nacimiento: "fecha_nacimiento",
    genero: "genero",
    sexo: "genero",
    estado_civil: "estado_civil",
    direccion: "direccion",
    telefono: "telefono",
    profesion: "profesion",
    centro: "centro",
    institucion: "institucion",
    colegio: "centro",
  };

  for (const linea of lineas) {
    const match = linea.match(/^([A-ZÁÉÍÓÚÑa-záéíóúñ\s]+)\s:\s(.+)$/);
    if (match) {
      let clave = match[1].trim().toLowerCase();
      const valor = match[2].trim();

      clave = clave.replace(/\s-\s\d+$/, "").trim();

      const claveLower = clave.toLowerCase();
      if (claveLower.includes("credits") || claveLower.includes("wanted")) {
        continue;
      }

      clave = clave
        .replace(/\s+/g, "_")
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "");

      const claveNormalizada = mapeoClaves[clave] || clave;

      if (!persona[claveNormalizada]) {
        persona[claveNormalizada] = valor;
      }
    }
  }

  return Object.keys(persona).length > 0 ? persona : null;
};

const formatearBusquedaNombres = (query) => {
  if (!query || typeof query !== "string") return query;

  const palabras = query
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .filter((p) => p.length > 0);

  if (palabras.length === 0) return query;

  if (palabras.length === 1) {
    return `${palabras[0]}||`;
  }

  if (palabras.length === 2) {
    return `${palabras[0]}|${palabras[1]}|`;
  }

  let nombres = [];
  let apellidoPaterno = "";
  let apellidoMaterno = "";

  const preposiciones = ["del", "de", "la", "las", "los", "san", "santa"];

  let indiceApellidoPaterno = palabras.length - 2;
  let indiceApellidoMaterno = palabras.length - 1;

  if (
    indiceApellidoPaterno > 0 &&
    preposiciones.includes(palabras[indiceApellidoPaterno - 1])
  ) {
    apellidoPaterno = palabras
      .slice(indiceApellidoPaterno - 1, indiceApellidoPaterno + 1)
      .join("+");
    nombres = palabras.slice(0, indiceApellidoPaterno - 1);
  } else {
    apellidoPaterno = palabras[indiceApellidoPaterno];
    nombres = palabras.slice(0, indiceApellidoPaterno);
  }

  apellidoMaterno = palabras[indiceApellidoMaterno];

  const nombresFormateados = nombres.join(",");

  return `${nombresFormateados}|${apellidoPaterno}|${apellidoMaterno}`;
};

// -----------------------------------------------------------------------------
// MIDDLEWARE DE AUTENTICACIÓN
// -----------------------------------------------------------------------------
const authMiddleware = async (req, res, next) => {
  if (req.method === "OPTIONS") {
    return next();
  }

  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      error: "Método no permitido. Solo se acepta POST.",
    });
  }

  const token = req.headers["x-api-key"];
  if (!token) {
    return res.status(401).json({
      success: false,
      error: "Falta el token de API (x-api-key)",
    });
  }

  try {
    const usersRef = db.collection("usuarios");
    const snapshot = await usersRef.where("apiKey", "==", token).limit(1).get();

    if (snapshot.empty) {
      return res.status(403).json({
        success: false,
        error: "Token inválido",
      });
    }

    const userDoc = snapshot.docs[0];
    const userData = userDoc.data();
    const userId = userDoc.id;

    const validPlans = ["creditos", "ilimitado"];
    if (!validPlans.includes(userData.tipoPlan)) {
      return res.status(403).json({
        success: false,
        error:
          "Tu plan no es válido o está deshabilitado. Recarga o contacta a soporte.",
      });
    }

    if (userData.tipoPlan === "creditos") {
      if ((userData.creditos ?? 0) <= 0) {
        return res.status(403).json({
          success: false,
          error: "Créditos insuficientes. Recarga para seguir consultando.",
        });
      }
    }

    if (userData.tipoPlan === "ilimitado") {
      const fechaActivacionRaw =
        userData.fechaActivacionIlimitado ||
        userData.fechaActivacion ||
        userData.fechaInicio ||
        userData.fecha_inicio ||
        null;

      const duracion =
        Number(
          userData.duracionIlimitadoDias ||
            userData.duracionDias ||
            userData.duracion ||
            0
        ) || 0;

      // Si existen ambos campos, se valida expiración.
      // Si no existen, no bloqueamos para evitar romper tu lógica actual.
      if (fechaActivacionRaw && duracion > 0) {
        const fechaActivacion = fechaActivacionRaw.toDate
          ? fechaActivacionRaw.toDate()
          : new Date(fechaActivacionRaw);

        if (!Number.isNaN(fechaActivacion.getTime())) {
          const fechaFin = new Date(fechaActivacion);
          fechaFin.setDate(fechaFin.getDate() + duracion);

          const hoy = new Date();
          if (hoy > fechaFin) {
            return res.status(403).json({
              success: false,
              error:
                "Sorpresa, tu plan ilimitado ha vencido, renueva tu plan para seguir consultando",
            });
          }
        }
      }
    }

    req.user = { id: userId, ...userData };
    next();
  } catch (error) {
    console.error("Error en middleware:", error);
    return res.status(500).json({
      success: false,
      error: "Error interno al validar el token",
    });
  }
};

const creditosMiddleware = (costo) => {
  return async (req, res, next) => {
    if (req.method === "OPTIONS") return next();

    const domain =
      req.headers.origin || req.headers.referer || "Unknown/Direct Access";

    if (req.user.tipoPlan === "creditos") {
      const currentCredits = req.user.creditos ?? 0;

      if (currentCredits < costo) {
        return res.status(403).json({
          success: false,
          error: `Créditos insuficientes. Se requieren ${costo} créditos para esta consulta.`,
        });
      }
    }

    req.logData = {
      domain,
      endpoint: req.originalUrl,
      userId: req.user.id,
      cost: costo,
      timestamp: new Date(),
    };

    next();
  };
};

// -----------------------------------------------------------------------------
// HELPERS GENERALES
// -----------------------------------------------------------------------------
const safeEncode = (value) => encodeURIComponent(String(value ?? ""));

const generateMetaData = () => {
  return {
    version: "3.0.0",
    timestamp: new Date().toISOString(),
    request_id: `req_${Math.random().toString(36).substring(2, 15)}`,
    server: "cluster-aws-pe-secure-01",
  };
};

const generateUserPlanData = (user) => {
  return {
    tipo: user.tipoPlan,
    creditosRestantes: user.tipoPlan === "creditos" ? user.creditos ?? 0 : null,
  };
};

const deducirCreditosFirebase = async (req, costo) => {
  if (req.user.tipoPlan !== "creditos" || costo <= 0) return;

  const userRef = db.collection("usuarios").doc(req.user.id);
  const currentTime = new Date();
  const domain = req.logData?.domain || "Unknown/Direct Access";

  await db.runTransaction(async (t) => {
    const freshUserDoc = await t.get(userRef);
    const currentCredits = freshUserDoc.data()?.creditos ?? 0;

    if (currentCredits < costo) {
      throw new Error("CREDITOS_INSUFICIENTES");
    }

    t.update(userRef, {
      creditos: admin.firestore.FieldValue.increment(-costo),
      ultimaConsulta: currentTime,
      ultimoConsumo: {
        endpoint: req.originalUrl,
        costo,
        fecha: currentTime,
        dominio: domain,
      },
    });
  });

  req.user.creditos = Math.max((req.user.creditos ?? 0) - costo, 0);
};

const guardarLogExterno = async (logData) => {
  if (!LOG_GUARDADO_BASE_URL) return;

  const horaConsulta = new Date(logData.timestamp).toISOString();
  const url = `${LOG_GUARDADO_BASE_URL}/log_consulta?host=${encodeURIComponent(
    logData.domain
  )}&hora=${encodeURIComponent(horaConsulta)}&endpoint=${encodeURIComponent(
    logData.endpoint
  )}&userId=${encodeURIComponent(logData.userId)}&costo=${encodeURIComponent(
    logData.cost
  )}`;

  try {
    await axios.get(url, { timeout: 5000 });
  } catch (e) {
    console.error("Error al guardar log en API externa:", e.message);
  }
};

const limpiarRespuestaProveedor = (data) => {
  if (!data || typeof data !== "object") return data;

  const cleaned = { ...data };

  delete cleaned["developed-by"];
  delete cleaned.credits;
  delete cleaned.bot_used;
  delete cleaned.bot;
  delete cleaned.chat_id;
  delete cleaned.watermark;
  delete cleaned.provider;

  if (cleaned.error && typeof cleaned.error === "string") {
    if (
      cleaned.error.includes("Token con falta de pago") ||
      cleaned.error.includes("token expirado") ||
      cleaned.error.includes("insufficient credits")
    ) {
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
      userPlan: generateUserPlanData(user),
    },
    disclaimer:
      "Información obtenida de fuentes públicas. El uso de estos datos es responsabilidad exclusiva del cliente según Ley 29733.",
  };
};

const enviarRespuestaFinal = (
  req,
  res,
  httpStatus,
  success,
  data,
  meta,
  statusOverride = null
) => {
  const respuesta = formatoRespuestaEstandar(success, data, req.user, meta);

  res.status(httpStatus).json(respuesta);

  // Auditoría asíncrona, sin bloquear la respuesta al cliente
  registrarAuditoriaDeConsulta(
    req,
    meta,
    success,
    data,
    httpStatus,
    statusOverride
  );
};

const consumirAPIProveedor = async (
  req,
  res,
  url,
  costo,
  aplicarLimpiezaEspecial = false
) => {
  const meta = generateMetaData();

  try {
    const response = await axios.get(url, {
      timeout: 30000,
    });

    let providerData = response.data;

    if (aplicarLimpiezaEspecial) {
      providerData = limpiarRespuestaEspecial(providerData);
    }

    providerData = limpiarRespuestaProveedor(providerData);

    // Mantener lógica actual de créditos
    await deducirCreditosFirebase(req, costo);

    // Mantener log externo sin bloquear la respuesta
    guardarLogExterno(req.logData).catch((error) => {
      console.error("Error guardando log externo:", error.message);
    });

    return enviarRespuestaFinal(req, res, 200, true, providerData, meta);
  } catch (error) {
    if (error.message === "CREDITOS_INSUFICIENTES") {
      return enviarRespuestaFinal(
        req,
        res,
        409,
        false,
        { error: "No fue posible descontar los créditos. Intenta nuevamente." },
        meta,
        "ERROR"
      );
    }

    const httpStatus = error.response?.status || 500;
    let providerData =
      error.response?.data || { error: "Error en la consulta, intenta nuevamente" };

    if (aplicarLimpiezaEspecial) {
      providerData = limpiarRespuestaEspecial(providerData);
    }

    providerData = limpiarRespuestaProveedor(providerData);

    const statusOverride = httpStatus === 404 ? "NO_RESULTS" : "ERROR";

    return enviarRespuestaFinal(
      req,
      res,
      httpStatus,
      false,
      providerData,
      meta,
      statusOverride
    );
  }
};

// -----------------------------------------------------------------------------
// ENDPOINTS
// -----------------------------------------------------------------------------

// 1. DNI por número (7 créditos) -> /v3/consulta/dni
app.post("/v3/consulta/dni", authMiddleware, creditosMiddleware(7), async (req, res) => {
  const { dni } = req.body;

  if (!dni) {
    return res
      .status(400)
      .json(
        formatoRespuestaEstandar(
          false,
          { error: "DNI requerido en el body" },
          req.user
        )
      );
  }

  await consumirAPIProveedor(
    req,
    res,
    `${API_URL_RENIEC}/reniec?dni=${safeEncode(dni)}`,
    7
  );
});

// 2. Telefonía por Documento (9 créditos) -> /v3/consulta/telefonia-doc
app.post("/v3/consulta/telefonia-doc", authMiddleware, creditosMiddleware(9), async (req, res) => {
  const { documento } = req.body;

  if (!documento) {
    return res
      .status(400)
      .json(
        formatoRespuestaEstandar(
          false,
          { error: "Documento requerido en el body" },
          req.user
        )
      );
  }

  await consumirAPIProveedor(
    req,
    res,
    `${API_URL_TELEFONIA}/telefonia-doc?documento=${safeEncode(documento)}`,
    9
  );
});

// 3. Telefonía por Número de Teléfono (8 créditos) -> /v3/consulta/telefonia-num
app.post("/v3/consulta/telefonia-num", authMiddleware, creditosMiddleware(8), async (req, res) => {
  const { numero } = req.body;

  if (!numero) {
    return res
      .status(400)
      .json(
        formatoRespuestaEstandar(
          false,
          { error: "Número requerido en el body" },
          req.user
        )
      );
  }

  await consumirAPIProveedor(
    req,
    res,
    `${API_URL_TELEFONIA}/telefonia-num?numero=${safeEncode(numero)}`,
    8
  );
});

// 4. Datos SUNARP (8 créditos) -> /v3/consulta/placa
app.post("/v3/consulta/placa", authMiddleware, creditosMiddleware(8), async (req, res) => {
  const { placa } = req.body;

  if (!placa) {
    return res
      .status(400)
      .json(
        formatoRespuestaEstandar(
          false,
          { error: "Placa requerida en el body" },
          req.user
        )
      );
  }

  await consumirAPIProveedor(
    req,
    res,
    `${API_URL_SUNARP}/vehiculos?placa=${safeEncode(placa)}`,
    8
  );
});

// 5. SUNAT por RUC (6 créditos) -> /v3/consulta/ruc
app.post("/v3/consulta/ruc", authMiddleware, creditosMiddleware(6), async (req, res) => {
  const { data } = req.body;

  if (!data) {
    return res
      .status(400)
      .json(
        formatoRespuestaEstandar(
          false,
          { error: "RUC requerido en el body" },
          req.user
        )
      );
  }

  const apiUrl = `${API_URL_SUNAT}${safeEncode(data)}?token=${safeEncode(
    TOKEN_SUNAT
  )}`;

  await consumirAPIProveedor(req, res, apiUrl, 6);
});

// 6. SUNAT por Razón Social (5 créditos) -> /v3/consulta/razon-social
app.post("/v3/consulta/razon-social", authMiddleware, creditosMiddleware(5), async (req, res) => {
  const { data } = req.body;

  if (!data) {
    return res
      .status(400)
      .json(
        formatoRespuestaEstandar(
          false,
          { error: "Razón social requerida en el body" },
          req.user
        )
      );
  }

  const API_URL_SUNAT_RAZON =
    process.env.API_URL_SUNAT_RAZON ||
    "https://banckend-poxyv1-cosultape-masitaprex.fly.dev";

  await consumirAPIProveedor(
    req,
    res,
    `${API_URL_SUNAT_RAZON}/sunat-razon?data=${safeEncode(data)}`,
    5
  );
});

// 7. Empresas donde figura (4 créditos) -> /v3/consulta/empresas
app.post("/v3/consulta/empresas", authMiddleware, creditosMiddleware(4), async (req, res) => {
  const { dni } = req.body;

  if (!dni) {
    return res
      .status(400)
      .json(
        formatoRespuestaEstandar(
          false,
          { error: "DNI requerido en el body" },
          req.user
        )
      );
  }

  await consumirAPIProveedor(
    req,
    res,
    `${API_URL_EMPRESAS}/empresas?dni=${safeEncode(dni)}`,
    4
  );
});

// 8. Matrimonios Registrados (6 créditos) -> /v3/consulta/matrimonios
app.post("/v3/consulta/matrimonios", authMiddleware, creditosMiddleware(6), async (req, res) => {
  const { dni } = req.body;

  if (!dni) {
    return res
      .status(400)
      .json(
        formatoRespuestaEstandar(
          false,
          { error: "DNI requerido en el body" },
          req.user
        )
      );
  }

  await consumirAPIProveedor(
    req,
    res,
    `${API_URL_MATRIMONIOS}/matrimonios?dni=${safeEncode(dni)}`,
    6
  );
});

// 9. BUSCAR DNI POR NOMBRES (5 créditos) -> /v3/consulta/buscar-dni
app.post("/v3/consulta/buscar-dni", authMiddleware, creditosMiddleware(5), async (req, res) => {
  const { nombres, apepaterno, apematerno } = req.body;

  if (!nombres || !apepaterno || !apematerno) {
    return res.status(400).json(
      formatoRespuestaEstandar(
        false,
        { error: "Nombres y apellidos requeridos en el body" },
        req.user
      )
    );
  }

  await consumirAPIProveedor(
    req,
    res,
    `${API_URL_DNI_NOMBRES}/dni_nombres?nombres=${safeEncode(
      nombres
    )}&apepaterno=${safeEncode(apepaterno)}&apematerno=${safeEncode(apematerno)}`,
    5,
    true
  );
});

// 10. BUSCAR CÉDULA POR NOMBRES (5 créditos) -> /v3/consulta/buscar-cedula
app.post("/v3/consulta/buscar-cedula", authMiddleware, creditosMiddleware(5), async (req, res) => {
  const { query } = req.body;

  if (!query) {
    return res
      .status(400)
      .json(
        formatoRespuestaEstandar(
          false,
          { error: "Query requerido en el body" },
          req.user
        )
      );
  }

  const queryFormateado = formatearBusquedaNombres(query);

  await consumirAPIProveedor(
    req,
    res,
    `${API_URL_VENEZOLANOS}/venezolanos_nombres?query=${safeEncode(
      queryFormateado
    )}`,
    5,
    true
  );
});

// 11. CONSULTAR CÉDULA (5 créditos) -> /v3/consulta/cedula
app.post("/v3/consulta/cedula", authMiddleware, creditosMiddleware(5), async (req, res) => {
  const { cedula } = req.body;

  if (!cedula) {
    return res
      .status(400)
      .json(
        formatoRespuestaEstandar(
          false,
          { error: "Cédula requerida en el body" },
          req.user
        )
      );
  }

  await consumirAPIProveedor(
    req,
    res,
    `${API_URL_CEDULA}/cedula?cedula=${safeEncode(cedula)}`,
    5,
    true
  );
});

// -----------------------------------------------------------------------------
// ENDPOINT RAÍZ (HEALTH CHECK)
// -----------------------------------------------------------------------------
app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "🚀 API Consulta PE Segura v3.0.0 funcionando",
    meta: generateMetaData(),
    security: {
      mode: "Strict POST",
      encryption: "TLS/SSL Enforced via Edge",
    },
    audit: {
      googleSheets: AUDIT_GOOGLE_SHEETS_ENABLED ? "enabled" : "disabled",
      zeroStoragePolicy: true,
    },
  });
});

// -----------------------------------------------------------------------------
// SERVER
// -----------------------------------------------------------------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Servidor Seguro corriendo en http://0.0.0.0:${PORT}`);
});
