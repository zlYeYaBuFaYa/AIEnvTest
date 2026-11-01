import React from "react";
import ReactDOM from "react-dom/client";
import { ThemeProvider } from "./lib/theme";
import App from "./App";
import { I18nProvider } from "./lib/i18n";
import "./index.css";

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <ThemeProvider>
      <I18nProvider>
        <App />
      </I18nProvider>
    </ThemeProvider>
  </React.StrictMode>,
);
