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