import React, { useState } from "react";
import "./App.css";

function App() {
  const [url, setUrl] = useState("");
  const [results, setResults] = useState(null);

  const handleScan = async () => {
    const response = await fetch("https://vulnsight-ai.onrender.com", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ url }),
    });

    const data = await response.json();
    setResults(data);
  };

  return (
    <div className="App">
      <h1>VulnSight AI</h1>
      <h2>Web Vulnerability Detection Platform</h2>

      <input
        type="text"
        placeholder="Enter website URL"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
      />

      <button onClick={handleScan}>Scan</button>

      {results && (
        <div style={{ marginTop: "20px" }}>
          <h3>Scan Results for: {results.target}</h3>
          <ul>
            {results.vulnerabilities.map((vuln, index) => (
              <li key={index}>
                <strong>{vuln.type}</strong> - {vuln.severity}
                <br />
                {vuln.description}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export default App;