const API_BASE_URL = "";

const API_ENDPOINTS = {
  analyze: `${API_BASE_URL}/api/reports/analyze`,
  reports: `${API_BASE_URL}/api/reports`,
  reportDetail: (reportId) => `${API_BASE_URL}/api/reports/${reportId}`
};

const fileInput = document.getElementById("fileInput");
const fileNameText = document.getElementById("fileNameText");
const analyzeBtn = document.getElementById("analyzeBtn");
const clearBtn = document.getElementById("clearBtn");
const refreshReportsBtn = document.getElementById("refreshReportsBtn");

const statusText = document.getElementById("statusText");
const historyStatusText = document.getElementById("historyStatusText");

const resultSection = document.getElementById("resultSection");

const reportList = document.getElementById("reportList");

const metadataText = document.getElementById("metadataText");

const summaryContent = document.getElementById("summaryContent");

const indicatorCount = document.getElementById("indicatorCount");

const toolCount = document.getElementById("toolCount");

const behaviorCount = document.getElementById("behaviorCount");

const mappingCount = document.getElementById("mappingCount");

const indicatorTableBody = document.getElementById("indicatorTableBody");

const toolTableBody = document.getElementById("toolTableBody");

const actorTableBody = document.getElementById("actorTableBody");

const behaviorTableBody = document.getElementById("behaviorTableBody");

const mappingTableBody = document.getElementById("mappingTableBody");

const recommendationList = document.getElementById("recommendationList");

let currentReportRecord = null;

document.addEventListener(
  "DOMContentLoaded",
  loadReportList
);

fileInput.addEventListener(
  "change",
  handleFileSelect
);

analyzeBtn.addEventListener(
  "click",
  analyzeFile
);

clearBtn.addEventListener(
  "click",
  clearFile
);

refreshReportsBtn.addEventListener(
  "click",
  loadReportList
);

function handleFileSelect() {
  const file = fileInput.files[0];

  fileNameText.textContent = file ? `已選擇檔案：${file.name}` : "尚未選擇檔案";

  setStatus("");
}

async function analyzeFile() {
  const file = fileInput.files[0];

  if (!file) {
    alert("請先選擇檔案");
    return;
  }

  setLoading(true);
  setStatus("正在上傳檔案並等待後端分析...");

  try {
    const response =
      await uploadReportToBackend(file);

    const reportRecord =
      normalizeReportRecord(
        response,
        file.name
      );

    currentReportRecord = reportRecord;

    renderReportRecord(reportRecord);

    setStatus(
      "分析完成，已成功接收 CTI。",
      "success"
    );

    await loadReportList();
  } catch (error) {
    console.error(error);

    setStatus(
      `分析失敗：${error.message}`,
      "error"
    );
  } finally {
    setLoading(false);
  }
}

async function uploadReportToBackend(file) {
  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch(
    API_ENDPOINTS.analyze,
    {
      method: "POST",
      body: formData
    }
  );

  const data = await response.json();

  if (!response.ok) {
    throw new Error(
      data.message ||
      `HTTP ${response.status}`
    );
  }

  return data;
}

async function loadReportList() {
  setHistoryStatus("正在載入歷史報告...");

  try {
    const reports =
      await fetchReportListFromBackend();

    renderReportList(reports);

    setHistoryStatus(
      `共載入 ${reports.length} 份歷史報告`,
      "success"
    );
  } catch (error) {
    console.error(error);

    setHistoryStatus(
      `歷史報告載入失敗：${error.message}`,
      "error"
    );
  }
}

async function fetchReportListFromBackend() {
  const response = await fetch(
    API_ENDPOINTS.reports
  );

  if (!response.ok) {
    throw new Error(
      `無法取得歷史報告列表：${response.status}`
    );
  }

  const payload = await response.json();

  if (!Array.isArray(payload)) {
    throw new Error(
      "歷史報告格式錯誤"
    );
  }

  return payload.map(
    normalizeReportListItem
  );
}

async function loadReportDetail(
  reportId
) {
  setStatus("正在載入歷史報告 CTI...");
  resultSection.classList.add("hidden");

  try {
    const response = await fetch(
      API_ENDPOINTS.reportDetail(reportId)
    );

    if (!response.ok) {
      throw new Error(
        `無法取得報告內容：${response.status}`
      );
    }

    const payload =
      await response.json();

    const reportRecord =
      normalizeReportRecord(payload);

    currentReportRecord =
      reportRecord;

    renderReportRecord(
      reportRecord
    );

    setStatus(
      "已成功載入歷史 CTI。",
      "success"
    );
  } catch (error) {
    console.error(error);

    setStatus(
      `載入失敗：${error.message}`,
      "error"
    );
  }
}

function normalizeReportRecord(
  payload,
  fallbackFilename = ""
) {
  const cti =
    payload.cti ||
    payload.cti_json ||
    payload;

  return {
    id: payload.id || "",
    filename:
      payload.filename ||
      fallbackFilename ||
      "未命名報告",
    createdAt:
      payload.created_at ||
      payload.createdAt ||
      "",
    model: payload.model || "",
    textCharCount:
      payload.text_char_count ??
      payload.textCharCount ??
      null,
    truncated: Boolean(payload.truncated),
    cti,
    validation: payload.validation || {},
    counts:
      payload.counts ||
      buildCounts(cti)
  };
}

function normalizeReportListItem(
  payload
) {
  return normalizeReportRecord(payload);
}

function buildCounts(cti) {
  return {
    indicators: arrayValue(cti.indicators).length,
    malware_or_tools: arrayValue(cti.malware_or_tools).length,
    threat_actors: arrayValue(cti.threat_actors).length,
    attack_behaviors: arrayValue(cti.attack_behaviors).length,
    attack_mapping: arrayValue(cti.attack_mapping).length,
    defensive_recommendations: arrayValue(cti.defensive_recommendations).length
  };
}

function renderReportRecord(
  reportRecord
) {
  const cti = reportRecord.cti || {};
  const counts = reportRecord.counts || buildCounts(cti);

  renderMetadata(reportRecord);
  renderSummary(cti.threat_summary || {});

  indicatorCount.textContent =
    String(counts.indicators || 0);
  toolCount.textContent =
    String(counts.malware_or_tools || 0);
  behaviorCount.textContent =
    String(counts.attack_behaviors || 0);
  mappingCount.textContent =
    String(counts.attack_mapping || 0);

  renderTable(
    indicatorTableBody,
    arrayValue(cti.indicators),
    [
      row => row.type,
      row => row.value,
      row => row.role,
      row => row.evidence,
      row => formatConfidence(row.confidence)
    ]
  );

  renderTable(
    toolTableBody,
    arrayValue(cti.malware_or_tools),
    [
      row => row.name,
      row => row.type,
      row => row.role,
      row => row.evidence,
      row => formatConfidence(row.confidence)
    ]
  );

  renderTable(
    actorTableBody,
    arrayValue(cti.threat_actors),
    [
      row => row.name,
      row => row.role || row.attribution_confidence,
      row => row.evidence,
      row => formatConfidence(row.confidence)
    ]
  );

  renderTable(
    behaviorTableBody,
    arrayValue(cti.attack_behaviors),
    [
      row => row.behavior,
      row => row.attack_stage,
      row => row.evidence,
      row => formatConfidence(row.confidence)
    ]
  );

  renderTable(
    mappingTableBody,
    arrayValue(cti.attack_mapping),
    [
      row => row.tactic,
      row => row.technique,
      row => row.mitre_id,
      row => row.evidence,
      row => formatConfidence(row.confidence)
    ]
  );

  renderRecommendations(
    arrayValue(cti.defensive_recommendations)
  );

  resultSection.classList.remove("hidden");
}

function renderMetadata(
  reportRecord
) {
  const parts = [
    reportRecord.filename
  ];

  if (reportRecord.createdAt) {
    parts.push(
      `建立時間：${formatDateTime(reportRecord.createdAt)}`
    );
  }

  if (reportRecord.model) {
    parts.push(
      `模型：${reportRecord.model}`
    );
  }

  if (reportRecord.textCharCount !== null) {
    parts.push(
      `抽取文字：${reportRecord.textCharCount} 字元`
    );
  }

  if (reportRecord.truncated) {
    parts.push("已截斷後送入模型");
  }

  metadataText.textContent = parts.join(" · ");
}

function renderSummary(
  summary
) {
  summaryContent.innerHTML = "";

  const entries = Object.entries(summary)
    .filter(([, value]) => value !== null && value !== "");

  if (entries.length === 0) {
    const empty = document.createElement("p");
    empty.className = "empty-message";
    empty.textContent = "模型未回傳威脅摘要。";
    summaryContent.appendChild(empty);
    return;
  }

  const list = document.createElement("dl");
  list.className = "summary-list";

  entries.forEach(([key, value]) => {
    const term = document.createElement("dt");
    term.textContent = key.replaceAll("_", " ");

    const detail = document.createElement("dd");
    detail.textContent = String(value);

    list.appendChild(term);
    list.appendChild(detail);
  });

  summaryContent.appendChild(list);
}

function renderTable(
  tableBody,
  rows,
  columns
) {
  tableBody.innerHTML = "";

  if (rows.length === 0) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.className = "empty-table-cell";
    cell.colSpan = columns.length;
    cell.textContent = "沒有可顯示的資料";
    row.appendChild(cell);
    tableBody.appendChild(row);
    return;
  }

  rows.forEach(item => {
    const row = document.createElement("tr");

    columns.forEach(getValue => {
      const cell = document.createElement("td");
      const value = getValue(item || {});
      cell.textContent =
        value === undefined ||
        value === null ||
        value === ""
          ? "-"
          : String(value);
      row.appendChild(cell);
    });

    tableBody.appendChild(row);
  });
}

function renderRecommendations(
  recommendations
) {
  recommendationList.innerHTML = "";

  if (recommendations.length === 0) {
    const item = document.createElement("li");
    item.className = "empty-message";
    item.textContent = "沒有防禦建議。";
    recommendationList.appendChild(item);
    return;
  }

  recommendations.forEach(recommendation => {
    const item = document.createElement("li");
    const mainText =
      recommendation.recommendation ||
      recommendation.text ||
      "-";
    const details = [
      recommendation.priority ? `優先級：${recommendation.priority}` : "",
      recommendation.related_behavior ? `相關行為：${recommendation.related_behavior}` : "",
      recommendation.confidence !== undefined ? `信心值：${formatConfidence(recommendation.confidence)}` : ""
    ].filter(Boolean);

    item.textContent = details.length > 0
      ? `${mainText}（${details.join("，")}）`
      : mainText;

    recommendationList.appendChild(item);
  });
}

function renderReportList(
  reports
) {
  reportList.innerHTML = "";

  if (reports.length === 0) {
    const empty = document.createElement("p");
    empty.className = "empty-message";
    empty.textContent = "目前沒有歷史報告。";
    reportList.appendChild(empty);
    return;
  }

  reports.forEach(report => {
    const item = document.createElement("button");
    item.type = "button";
    item.className = "report-item";
    item.addEventListener(
      "click",
      () => loadReportDetail(report.id)
    );

    const title = document.createElement("strong");
    title.textContent = report.filename;

    const meta = document.createElement("span");
    meta.textContent = [
      report.createdAt ? formatDateTime(report.createdAt) : "",
      report.model || ""
    ].filter(Boolean).join(" · ");

    const summary = document.createElement("small");
    summary.textContent =
      report.cti?.threat_summary?.main_threat ||
      report.summary?.main_threat ||
      "尚無摘要";

    item.appendChild(title);
    item.appendChild(meta);
    item.appendChild(summary);
    reportList.appendChild(item);
  });
}

function clearFile() {
  fileInput.value = "";
  fileNameText.textContent = "尚未選擇檔案";
  currentReportRecord = null;
  resultSection.classList.add("hidden");
  setStatus("");
}

function setLoading(
  isLoading
) {
  analyzeBtn.disabled = isLoading;
  clearBtn.disabled = isLoading;
  fileInput.disabled = isLoading;
}

function setStatus(
  message,
  type = ""
) {
  statusText.textContent = message;
  statusText.className = type
    ? `status ${type}`
    : "status";
}

function setHistoryStatus(
  message,
  type = "muted"
) {
  historyStatusText.textContent = message;
  historyStatusText.className = type
    ? `status ${type}`
    : "status muted";
}

function arrayValue(
  value
) {
  return Array.isArray(value) ? value : [];
}

function formatConfidence(
  value
) {
  if (value === undefined || value === null || value === "") {
    return "-";
  }

  const number = Number(value);

  if (Number.isNaN(number)) {
    return String(value);
  }

  return number.toFixed(2);
}

function formatDateTime(
  value
) {
  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleString("zh-TW");
}
