const BACKEND_URL = "http://127.0.0.1:8000/predict";

const form = document.getElementById("url-form");
const urlInput = document.getElementById("url-input");
const loadingDiv = document.getElementById("loading");
const resultBox = document.getElementById("result-box");
const resultBadge = document.getElementById("result-badge");
const confidenceScore = document.getElementById("confidence-score");
const resultExplanation = document.getElementById("result-explanation");
const featureGrid = document.getElementById("feature-grid");

function setURL(sampleUrl) {
  urlInput.value = sampleUrl;
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const rawUrl = urlInput.value.trim();
  if (!rawUrl) return;

  // Show loading indicator
  loadingDiv.classList.remove("hidden");
  resultBox.classList.add("hidden");

  try {
    // Send POST request directly to the FastAPI server
    const response = await fetch(BACKEND_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: rawUrl })
    });

    if (!response.ok) {
      throw new Error(`Server returned error: ${response.statusText}`);
    }

    const data = await response.json();

    // Display prediction card
    resultBox.className = "result-box " + (data.is_phishing ? "danger" : "safe");
    resultBadge.textContent = data.prediction;
    confidenceScore.textContent = `${data.confidence}% Confidence`;

    if (data.is_phishing) {
      resultExplanation.textContent =
        "Warning: This URL displays statistical and structural anomalies (such as token manipulation, suspicious keywords, or excessive subdomains) commonly seen in phishing and scam campaigns.";
    } else {
      resultExplanation.textContent =
        "This URL matches structural indicators of benign domains. However, standard cybersecurity caution is always recommended.";
    }

    // Populate feature grid
    featureGrid.innerHTML = Object.entries(data.features)
      .map(([k, v]) => `<div class="feature-item">${k}: <strong>${v}</strong></div>`)
      .join("");

    resultBox.classList.remove("hidden");
  } catch (err) {
    alert("Connection Error: Make sure the FastAPI backend is running on port 8000.\n\n" + err.message);
  } finally {
    loadingDiv.classList.add("hidden");
  }
});