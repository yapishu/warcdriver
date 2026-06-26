import React from "react";
import ReactDOM from "react-dom/client";
import { App } from "./App";
import { registerAppServiceWorker } from "./pwa";
import "./styles.css";

registerAppServiceWorker();

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
