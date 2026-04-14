import React, { useState } from "react";
import { FaChevronDown, FaChevronUp } from "react-icons/fa";
import { IoMdDownload } from "react-icons/io";
import {
  Card,
  Header,
  Conteudo,
  ButtonRow,
  Button,
  Data,
  Divider,
  NumeroAmostra,
} from "./styled";

const API_BASE_URL = (
  import.meta.env.VITE_API_BASE_URL || "https://gaia-2spq.onrender.com"
).replace(/\/$/, "");

const resolvePdfUrl = (rawUrl) => {
  if (!rawUrl) return null;
  if (/^https?:\/\//i.test(rawUrl)) return rawUrl;
  const normalizedPath = rawUrl.startsWith("/") ? rawUrl : `/${rawUrl}`;
  return `${API_BASE_URL}${normalizedPath}`;
};

const ReportCard = ({ data, amostras }) => {
  const [expandido, setExpandido] = useState(false);

  const formatarDataBR = (dataString) => {
    // Se já estiver no formato BR, retorna como está
    if (dataString && dataString.includes("/")) {
      return dataString;
    }

    try {
      // Converte YYYY-MM-DD para DD/MM/YYYY
      if (dataString && dataString.includes("-")) {
        const [ano, mes, dia] = dataString.split("-");
        return `${dia}/${mes}/${ano}`;
      }

      // Tenta converter data ISO
      const date = new Date(dataString);
      if (!isNaN(date.getTime())) {
        return date.toLocaleDateString("pt-BR");
      }

      return dataString || "Data não disponível";
    } catch {
      return dataString || "Data não disponível";
    }
  };

  return (
    <Card>
      <Header
        type="button"
        onClick={() => setExpandido(!expandido)}
        aria-expanded={expandido}
      >
        <Data>
          <strong>Data da coleta:</strong> {formatarDataBR(data)}
        </Data>
        {expandido ? <FaChevronUp /> : <FaChevronDown />}
      </Header>

      <Conteudo $expandido={expandido}>
        {amostras.map((laudo, index) => {
          const pdfUrl = resolvePdfUrl(laudo.arquivoUrl);

          return (
            <React.Fragment key={laudo.id}>
              <div>
                <NumeroAmostra>
                  <strong>Número da amostra:</strong> {laudo.numero}
                </NumeroAmostra>

                {pdfUrl ? (
                  <ButtonRow>
                    <a
                      href={pdfUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{ textDecoration: "none" }}
                    >
                      <Button>Visualizar</Button>
                    </a>
                    <Button
                      onClick={() => {
                        try {
                          const link = document.createElement("a");
                          link.href = pdfUrl;
                          link.target = "_blank";
                          link.rel = "noopener noreferrer";
                          link.download =
                            pdfUrl.split("/").pop() || "laudo.pdf";
                          document.body.appendChild(link);
                          link.click();
                          document.body.removeChild(link);
                        } catch (error) {
                          console.error("Erro ao baixar o PDF:", error);
                        }
                      }}
                    >
                      Baixar <IoMdDownload size={20} />
                    </Button>
                  </ButtonRow>
                ) : (
                  <p style={{ color: "#999", fontSize: "14px" }}>
                    Laudo ainda não possui arquivo PDF anexado
                  </p>
                )}
              </div>
              {index < amostras.length - 1 && <Divider />}
            </React.Fragment>
          );
        })}
      </Conteudo>
    </Card>
  );
};

export default ReportCard;
