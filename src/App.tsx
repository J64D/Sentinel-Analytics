import { useCallback, useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import {
  Activity, AlertOctagon, AlertTriangle, ArrowDownRight, ArrowUpRight, Bell,
  Check, ChevronDown, ChevronRight, CircleHelp, Clock3, FileClock, Fingerprint,
  Globe2, LayoutDashboard, LockKeyhole, Plus, RefreshCw, Search, Server,
  Settings2, Shield, ShieldAlert, ShieldCheck, Siren, X,
} from "lucide-react";
import "./styles.css";

type View = "overview" | "events" | "alerts" | "risk" | "audit";
type SecurityEvent = {
  id: string;
  eventType: string;
  actorEmail: string;
  sourceIp: string;
  sourceSystem: string;
  resource: string | null;
  outcome: "success" | "failure";
  occurredAt: string;
};
type Alert = {
  id: string;
  eventId: string;
  ruleKey: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  title: string;
  description: string;
  status: "OPEN" | "INVESTIGATING" | "RESOLVED";
  createdAt: string;
  updatedAt: string;
  resolutionNote?: string | null;
};
type Overview = {
  metrics: { events24h: number; authFailures24h: number; activeAlerts: number };
  recentEvents: SecurityEvent[];
  recentAlerts: Alert[];
};
type RiskAnalysis = {
  metodologia?: string;
  data_analise?: string;
  total_nao_conformidades_analisadas?: number;
  matriz_risco?: {
    criticidade?: string;
    score_final?: number;
    detalhes?: {
      analise_transversal?: string;
      acao_preventiva_imediata?: string;
      impacto_score?: number;
      probabilidade_score?: number;
      analysis_source?: "GROQ" | "DETERMINISTIC_FALLBACK";
    };
  };
  dados_origem?: Array<{
    id_auditoria: string;
    setor: string;
    item_controle: string;
    status: string;
    evidencia_descrita: string;
  }>;
};
type AuditEntry = {
  id: string;
  kind: "EVENT" | "ALERT_STATUS";
  action: string;
  actor: string;
  detail: string;
  outcome: string;
  createdAt: string;
};

const SENTINEL_API_BASE = (import.meta.env.VITE_SENTINEL_API_BASE_URL || "http://localhost:3001/api/v1").replace(/\/$/, "");
const PREDICTIVE_API_BASE = (import.meta.env.VITE_PREDICTIVE_API_BASE_URL || "http://localhost:3000/api/v1").replace(/\/$/, "");
const emptyOverview: Overview = {
  metrics: { events24h: 0, authFailures24h: 0, activeAlerts: 0 },
  recentEvents: [],
  recentAlerts: [],
};
const navItems: Array<{ id: View; label: string; icon: typeof LayoutDashboard }> = [
  { id: "overview", label: "Visão geral", icon: LayoutDashboard },
  { id: "events", label: "Eventos", icon: Activity },
  { id: "alerts", label: "Alertas", icon: Siren },
  { id: "risk", label: "Risco ISO 31000", icon: ShieldCheck },
  { id: "audit", label: "Trilha de auditoria", icon: FileClock },
];

async function apiRequest<T>(baseUrl: string, path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  if (init?.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  const response = await fetch(`${baseUrl}${path}`, {
    ...init,
    headers,
  });
  if (!response.ok) {
    const body = await response.json().catch(() => null) as {
      error?: string;
      details?: Array<{ field: string; message: string }>;
    } | null;
    const details = body?.details?.map(({ field, message }) => `${field}: ${message}`).join("; ");
    throw new Error([body?.error, details].filter(Boolean).join(" ") || `Falha na API (${response.status}).`);
  }
  return response.json() as Promise<T>;
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat("pt-BR", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function eventLabel(eventType: string) {
  const labels: Record<string, string> = {
    "login.success": "Login autorizado",
    "login.failure": "Falha de autenticação",
    "mfa.failure": "Falha no MFA",
    "privilege.change": "Alteração de privilégio",
    "policy.change": "Alteração de política",
    "sensitive.access": "Acesso sensível",
  };
  return labels[eventType] || eventType;
}

function severityLabel(severity: string) {
  return ({ CRITICAL: "Crítico", HIGH: "Alto", MEDIUM: "Médio", LOW: "Baixo" } as Record<string, string>)[severity] || severity;
}

function errorMessage(reason: unknown) {
  return reason instanceof Error ? reason.message : String(reason);
}

function statusLabel(status: string) {
  return ({ OPEN: "Aberto", INVESTIGATING: "Em investigação", RESOLVED: "Resolvido" } as Record<string, string>)[status] || status;
}

function App() {
  const [view, setView] = useState<View>("overview");
  const [overview, setOverview] = useState<Overview>(emptyOverview);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [auditLog, setAuditLog] = useState<AuditEntry[]>([]);
  const [risk, setRisk] = useState<RiskAnalysis | null>(null);
  const [errors, setErrors] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [modalOpen, setModalOpen] = useState(false);
  const [busyAlert, setBusyAlert] = useState<string | null>(null);
  const [toast, setToast] = useState("");

  const loadData = useCallback(async (quiet = false) => {
    if (quiet) setRefreshing(true);
    else setLoading(true);
    const results = await Promise.allSettled([
      apiRequest<Overview>(SENTINEL_API_BASE, "/security/overview"),
      apiRequest<SecurityEvent[]>(SENTINEL_API_BASE, "/security/events?limit=100"),
      apiRequest<Alert[]>(SENTINEL_API_BASE, "/security/alerts?limit=100"),
      apiRequest<AuditEntry[]>(SENTINEL_API_BASE, "/security/audit-log?limit=100"),
      apiRequest<RiskAnalysis>(PREDICTIVE_API_BASE, "/board/executive-summary"),
    ]);
    const failures: string[] = [];
    if (results[0].status === "fulfilled") setOverview(results[0].value);
    else failures.push(`Visão de segurança: ${errorMessage(results[0].reason)}`);
    if (results[1].status === "fulfilled") setEvents(results[1].value);
    else failures.push(`Eventos: ${errorMessage(results[1].reason)}`);
    if (results[2].status === "fulfilled") setAlerts(results[2].value);
    else failures.push(`Alertas: ${errorMessage(results[2].reason)}`);
    if (results[3].status === "fulfilled") setAuditLog(results[3].value);
    else failures.push(`Auditoria: ${errorMessage(results[3].reason)}`);
    if (results[4].status === "fulfilled") setRisk(results[4].value);
    else failures.push(`Análise ISO 31000: ${errorMessage(results[4].reason)}`);
    setErrors(failures);
    setLoading(false);
    setRefreshing(false);
  }, []);

  useEffect(() => {
    void loadData();
    const timer = window.setInterval(() => void loadData(true), 15_000);
    return () => window.clearInterval(timer);
  }, [loadData]);

  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(""), 3800);
    return () => window.clearTimeout(timer);
  }, [toast]);

  const openAlerts = useMemo(() => alerts.filter((alert) => alert.status !== "RESOLVED"), [alerts]);

  async function changeAlert(alert: Alert, status: "INVESTIGATING" | "RESOLVED") {
    const note = status === "RESOLVED" ? window.prompt("Nota de resolução (opcional):") : undefined;
    if (status === "RESOLVED" && note === null) return;
    setBusyAlert(alert.id);
    try {
      await apiRequest<Alert>(SENTINEL_API_BASE, `/security/alerts/${alert.id}`, {
        method: "PATCH",
        body: JSON.stringify({ status, ...(note ? { note } : {}) }),
      });
      setToast(`Alerta atualizado: ${statusLabel(status).toLowerCase()}.`);
      await loadData(true);
    } catch (error) {
      setToast(error instanceof Error ? error.message : "Não foi possível atualizar o alerta.");
    } finally {
      setBusyAlert(null);
    }
  }

  async function createEvent(payload: Record<string, string>) {
    await apiRequest(SENTINEL_API_BASE, "/security/events", { method: "POST", body: JSON.stringify(payload) });
    setModalOpen(false);
    setToast("Evento de segurança registrado.");
    await loadData(true);
  }

  const currentLabel = navItems.find((item) => item.id === view)?.label || "Visão geral";

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-lockup">
          <div className="brand-mark"><Shield size={20} strokeWidth={2.2} /></div>
          <div className="brand-text"><strong>Sentinel</strong><span>SECURITY OPERATIONS</span></div>
        </div>
        <div className="workspace-switch"><span className="workspace-avatar">J</span><span><b>J64D Security Lab</b><small>Workspace principal</small></span><ChevronDown size={15} /></div>
        <div className="nav-section-label">MONITORAMENTO</div>
        <nav className="side-nav" aria-label="Navegação principal">
          {navItems.map(({ id, label, icon: Icon }) => (
            <button key={id} className={`nav-link ${view === id ? "active" : ""}`} onClick={() => setView(id)}>
              <Icon size={17} strokeWidth={1.8} /><span>{label}</span>
              {id === "alerts" && openAlerts.length > 0 && <span className="nav-count">{openAlerts.length}</span>}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="environment-card">
            <span className="environment-dot" />
            <span><b>Ambiente local</b><small>Atualização a cada 15 s</small></span>
            <Settings2 size={15} />
          </div>
          <div className="profile-row"><span className="profile-avatar">J</span><span><b>J64D Security</b><small>Operador</small></span><CircleHelp size={16} /></div>
          <div className="powered">POWERED FOR <b>J64D</b></div>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div className="breadcrumbs"><span>Sentinel</span><ChevronRight size={14} /><strong>{currentLabel}</strong></div>
          <div className="topbar-actions">
            <div className="connection-state"><span className={`connection-dot ${errors.length ? "offline" : ""}`} />{errors.length ? "Conexão parcial" : "Monitoramento ativo"}</div>
            <button className={`icon-button ${refreshing ? "spinning" : ""}`} aria-label="Atualizar dados" onClick={() => void loadData(true)}><RefreshCw size={17} /></button>
            <button className="icon-button notification-button" aria-label={`${openAlerts.length} alertas ativos`} onClick={() => setView("alerts")}><Bell size={17} />{openAlerts.length > 0 && <i />}</button>
            <span className="top-avatar">JD</span>
          </div>
        </header>

        <div className="page-content">
          <div className="page-heading">
            <div>
              <div className="eyebrow"><span className="live-pulse" /> SECURITY OPERATIONS CENTER <span className="eyebrow-divider">/</span> {new Intl.DateTimeFormat("pt-BR", { dateStyle: "full" }).format(new Date())}</div>
              <h1>{view === "overview" ? "Postura de segurança" : currentLabel}</h1>
              <p>{view === "overview" ? "Eventos, alertas e riscos em uma única visão operacional." : sectionDescription(view)}</p>
            </div>
            <div className="heading-actions">
              <button className="button button-secondary" onClick={() => void loadData(true)}><RefreshCw size={15} /> Atualizar</button>
              <button className="button button-primary" onClick={() => setModalOpen(true)}><Plus size={16} /> Registrar evento</button>
            </div>
          </div>

          {errors.length > 0 && <div className="error-banner" role="status"><AlertTriangle size={17} /><div><b>Alguns serviços não responderam.</b><span>{errors.join(" · ")}</span></div><button onClick={() => void loadData(true)} aria-label="Tentar novamente"><RefreshCw size={15} /></button></div>}

          {view === "overview" && <OverviewPage overview={overview} events={events.slice(0, 6)} alerts={openAlerts.slice(0, 5)} risk={risk} onView={setView} onAlertAction={changeAlert} busyAlert={busyAlert} loading={loading} />}
          {view === "events" && <EventsPage events={events} loading={loading} />}
          {view === "alerts" && <AlertsPage alerts={alerts} loading={loading} onAlertAction={changeAlert} busyAlert={busyAlert} />}
          {view === "risk" && <RiskPage risk={risk} loading={loading} onView={() => setView("audit")} />}
          {view === "audit" && <AuditPage entries={auditLog} loading={loading} />}
          <footer className="page-footer"><span>Sentinel · Auditoria e resposta a eventos</span><span>Dados persistidos em PostgreSQL <i /> Motor de risco ISO 31000</span></footer>
        </div>
      </main>
      {modalOpen && <EventModal onClose={() => setModalOpen(false)} onSubmit={createEvent} />}
      {toast && <div className="toast" role="status"><Check size={16} />{toast}</div>}
    </div>
  );
}

function sectionDescription(view: View) {
  return ({
    events: "Registro normalizado de atividade e autenticação.",
    alerts: "Investigue, documente e encerre alertas gerados por regras explícitas.",
    risk: "Riscos transversais do projeto de auditoria preditiva ISO 31000.",
    audit: "Linha do tempo imutável de eventos e mudanças de estado dos alertas.",
    overview: "",
  })[view];
}

function MetricCard({ label, value, note, icon: Icon, tone, trend }: { label: string; value: string | number; note: string; icon: typeof Activity; tone: string; trend?: "up" | "down" }) {
  return <article className="metric-card"><div className="metric-topline"><span>{label}</span><div className={`metric-icon ${tone}`}><Icon size={17} /></div></div><strong>{value}</strong><div className="metric-note"><span>{note}</span>{trend && <b className={trend === "up" ? "trend-danger" : "trend-good"}>{trend === "up" ? <ArrowUpRight size={13} /> : <ArrowDownRight size={13} />} {trend === "up" ? "Atenção" : "Controlado"}</b>}</div></article>;
}

function OverviewPage({ overview, events, alerts, risk, onView, onAlertAction, busyAlert, loading }: {
  overview: Overview; events: SecurityEvent[]; alerts: Alert[]; risk: RiskAnalysis | null; onView: (view: View) => void;
  onAlertAction: (alert: Alert, status: "INVESTIGATING" | "RESOLVED") => void; busyAlert: string | null; loading: boolean;
}) {
  const riskScore = risk?.matriz_risco?.score_final;
  return <>
    <section className="metrics-grid">
      <MetricCard label="Eventos · 24 horas" value={overview.metrics.events24h} note="Eventos registrados" icon={Activity} tone="teal" />
      <MetricCard label="Falhas de autenticação" value={overview.metrics.authFailures24h} note="Login e MFA · 24 horas" icon={Fingerprint} tone="amber" trend={overview.metrics.authFailures24h > 0 ? "up" : undefined} />
      <MetricCard label="Alertas ativos" value={overview.metrics.activeAlerts} note="Abertos ou em investigação" icon={ShieldAlert} tone="red" trend={overview.metrics.activeAlerts > 0 ? "up" : undefined} />
      <MetricCard label="Score de risco" value={riskScore ?? "—"} note={risk?.matriz_risco?.criticidade ? `ISO 31000 · ${risk.matriz_risco.criticidade}` : "Análise indisponível"} icon={AlertOctagon} tone="violet" />
    </section>

    <section className="overview-grid">
      <Panel className="alerts-panel" title="Fila de alertas" description="Prioridade e atividade recente" icon={<Siren size={16} />}>
        <button className="panel-link" onClick={() => onView("alerts")}>Ver fila <ChevronRight size={14} /></button>
        {loading && alerts.length === 0 ? <LoadingRows /> : alerts.length === 0 ? <EmptyState icon={<ShieldCheck size={20} />} title="Nenhum alerta ativo" detail="Alertas aparecerão aqui quando uma regra de detecção for acionada." /> :
          <div className="alert-list">{alerts.map((alert) => <AlertRow key={alert.id} alert={alert} onAction={onAlertAction} busy={busyAlert === alert.id} compact />)}</div>}
      </Panel>
      <Panel className="risk-panel" title="Auditoria preditiva" description="Risco transversal · ISO 31000" icon={<ShieldCheck size={16} />}>
        <div className="risk-gauge"><div className="gauge-value">{riskScore ?? "—"}<small>/ 25</small></div><div className="gauge-copy"><span className={`severity-badge ${(risk?.matriz_risco?.criticidade || "unknown").toLowerCase()}`}>{risk?.matriz_risco?.criticidade || "Sem análise"}</span><small>{risk?.total_nao_conformidades_analisadas ?? 0} não conformidades avaliadas</small></div></div>
        <div className="risk-summary">{risk?.matriz_risco?.detalhes?.analise_transversal || "A análise consolidada ficará disponível quando o serviço de riscos responder."}</div>
        {risk?.matriz_risco?.detalhes?.analysis_source && <div className={`risk-source ${risk.matriz_risco.detalhes.analysis_source === "DETERMINISTIC_FALLBACK" ? "fallback" : ""}`}><Activity size={12} />{risk.matriz_risco.detalhes.analysis_source === "GROQ" ? "Análise do provedor de IA" : "Estimativa determinística · contingência"}</div>}
        <button className="risk-link" onClick={() => onView("risk")}>Abrir análise <ChevronRight size={14} /></button>
      </Panel>
    </section>

    <section className="content-grid">
      <Panel className="events-panel" title="Eventos recentes" description="Últimas atividades recebidas" icon={<Activity size={16} />} action={<button className="panel-link" onClick={() => onView("events")}>Todos os eventos <ChevronRight size={14} /></button>}>
        {loading && events.length === 0 ? <LoadingRows /> : <EventTable events={events} compact />}
      </Panel>
      <Panel className="signals-panel" title="Sinais monitorados" description="Regras de detecção em produção" icon={<LockKeyhole size={16} />}>
        <div className="signal-row"><span className="signal-icon danger"><Fingerprint size={16} /></span><span><b>Rajada de falhas de login</b><small>5 tentativas em 5 minutos por usuário e IP</small></span><span className="signal-status">ATIVO</span></div>
        <div className="signal-row"><span className="signal-icon danger"><ShieldAlert size={16} /></span><span><b>Falhas consecutivas de MFA</b><small>3 tentativas em 5 minutos por usuário e IP</small></span><span className="signal-status">ATIVO</span></div>
        <div className="signal-row"><span className="signal-icon warning"><Settings2 size={16} /></span><span><b>Alteração de privilégios</b><small>Gera alerta crítico para investigação</small></span><span className="signal-status">ATIVO</span></div>
        <div className="signals-foot"><Globe2 size={14} /> Regras determinísticas · Sem execução automática de ações</div>
      </Panel>
    </section>
  </>;
}

function Panel({ title, description, icon, action, className = "", children }: { title: string; description: string; icon: ReactNode; action?: ReactNode; className?: string; children: ReactNode }) {
  return <section className={`panel ${className}`}><div className="panel-heading"><div className="panel-title"><span className="panel-heading-icon">{icon}</span><div><h2>{title}</h2><p>{description}</p></div></div>{action}</div>{children}</section>;
}

function AlertRow({ alert, onAction, busy, compact = false }: { alert: Alert; onAction: (alert: Alert, status: "INVESTIGATING" | "RESOLVED") => void; busy: boolean; compact?: boolean }) {
  return <div className={`alert-row ${compact ? "compact" : ""}`}>
    <div className={`severity-stripe ${alert.severity.toLowerCase()}`} />
    <div className="alert-main"><div className="alert-title-line"><span className={`severity-badge ${alert.severity.toLowerCase()}`}>{severityLabel(alert.severity)}</span><b>{alert.title}</b><span className={`status-pill ${alert.status.toLowerCase()}`}>{statusLabel(alert.status)}</span></div><p>{alert.description}</p><small><Clock3 size={12} /> {formatDate(alert.updatedAt)}</small></div>
    <div className="alert-actions">{alert.status === "OPEN" && <button className="text-action" disabled={busy} onClick={() => onAction(alert, "INVESTIGATING")}>{busy ? "Salvando..." : "Investigar"}</button>}{alert.status !== "RESOLVED" && <button className="resolve-button" disabled={busy} onClick={() => onAction(alert, "RESOLVED")} aria-label="Resolver alerta"><Check size={15} /></button>}</div>
  </div>;
}

function EventsPage({ events, loading }: { events: SecurityEvent[]; loading: boolean }) {
  const [search, setSearch] = useState("");
  const filteredEvents = events.filter((event) => [event.actorEmail, event.sourceIp, event.sourceSystem, event.eventType].join(" ").toLowerCase().includes(search.toLowerCase()));
  return <Panel className="full-panel" title="Registro de eventos" description={`${events.length} eventos carregados · máximo de 100`} icon={<Activity size={16} />} action={<label className="table-search"><Search size={15} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Buscar eventos" /></label>}>
    {loading && events.length === 0 ? <LoadingRows /> : <EventTable events={filteredEvents} />}
  </Panel>;
}

function EventTable({ events, compact = false }: { events: SecurityEvent[]; compact?: boolean }) {
  if (events.length === 0) return <EmptyState icon={<Activity size={20} />} title="Nenhum evento registrado" detail="Registre um evento ou conecte sua fonte de logs para iniciar o monitoramento." />;
  return <div className="table-scroll"><table className="data-table"><thead><tr><th>Tipo de evento</th><th>Identidade</th><th>Origem</th><th>Resultado</th><th>Data e hora</th></tr></thead><tbody>{events.map((event) => <tr key={event.id}><td><span className={`event-glyph ${event.outcome}`}><EventIcon eventType={event.eventType} /></span><span className="event-label">{eventLabel(event.eventType)}<small>{event.sourceSystem}{event.resource ? ` · ${event.resource}` : ""}</small></span></td><td className="identity-cell">{event.actorEmail}</td><td className="mono-cell">{event.sourceIp}</td><td><span className={`outcome-pill ${event.outcome}`}>{event.outcome === "success" ? "Sucesso" : "Falha"}</span></td><td className="date-cell">{formatDate(event.occurredAt)}</td></tr>)}</tbody></table>{compact && events.length >= 6 && <div className="table-footnote">Exibindo os 6 eventos mais recentes</div>}</div>;
}

function EventIcon({ eventType }: { eventType: string }) {
  return eventType.includes("login") || eventType.includes("mfa") ? <Fingerprint size={15} /> : eventType === "privilege.change" ? <ShieldAlert size={15} /> : <Server size={15} />;
}

function AlertsPage({ alerts, loading, onAlertAction, busyAlert }: { alerts: Alert[]; loading: boolean; onAlertAction: (alert: Alert, status: "INVESTIGATING" | "RESOLVED") => void; busyAlert: string | null }) {
  const [filter, setFilter] = useState("ALL");
  const filtered = alerts.filter((alert) => filter === "ALL" || alert.status === filter);
  return <Panel className="full-panel" title="Gestão de alertas" description="Da detecção à resolução, com histórico de estado" icon={<Siren size={16} />} action={<div className="segmented-control">{["ALL", "OPEN", "INVESTIGATING", "RESOLVED"].map((status) => <button key={status} className={filter === status ? "selected" : ""} onClick={() => setFilter(status)}>{status === "ALL" ? "Todos" : statusLabel(status)}</button>)}</div>}>
    {loading && alerts.length === 0 ? <LoadingRows /> : filtered.length === 0 ? <EmptyState icon={<ShieldCheck size={20} />} title="Nenhum alerta nesta fila" detail="Alertas serão criados automaticamente quando regras de segurança forem acionadas." /> : <div className="alert-list alert-list-full">{filtered.map((alert) => <AlertRow key={alert.id} alert={alert} onAction={onAlertAction} busy={busyAlert === alert.id} />)}</div>}
  </Panel>;
}

function RiskPage({ risk, loading, onView }: { risk: RiskAnalysis | null; loading: boolean; onView: () => void }) {
  if (!risk) return <Panel title="Motor de risco indisponível" description="Não foi possível carregar a API de auditoria" icon={<AlertTriangle size={16} />}><EmptyState icon={<Globe2 size={20} />} title={loading ? "Carregando análise" : "Serviço sem resposta"} detail="Confirme se o backend e a chave do provedor de IA (opcional) estão configurados." /></Panel>;
  return <>
    <section className="risk-detail-grid">
      <article className="risk-score-card"><span className="eyebrow">MATRIZ DE RISCO · ISO 31000</span><div className="large-score">{risk.matriz_risco?.score_final ?? "—"}<small>/ 25</small></div><span className={`severity-badge ${(risk.matriz_risco?.criticidade || "unknown").toLowerCase()}`}>{risk.matriz_risco?.criticidade || "Sem criticidade"}</span><p>{risk.matriz_risco?.detalhes?.analise_transversal || "Sem análise transversal disponível."}</p><div className="score-formula">Impacto ({risk.matriz_risco?.detalhes?.impacto_score ?? "—"}) × Probabilidade ({risk.matriz_risco?.detalhes?.probabilidade_score ?? "—"})</div>{risk.matriz_risco?.detalhes?.analysis_source && <div className={`risk-source ${risk.matriz_risco.detalhes.analysis_source === "DETERMINISTIC_FALLBACK" ? "fallback" : ""}`}><Activity size={12} />{risk.matriz_risco.detalhes.analysis_source === "GROQ" ? "Análise do provedor de IA" : "Estimativa determinística · contingência"}</div>}</article>
      <Panel title="Ação preventiva" description="Recomendação do motor de análise" icon={<ShieldCheck size={16} />}><div className="recommendation"><div className="recommendation-icon"><AlertTriangle size={18} /></div><p>{risk.matriz_risco?.detalhes?.acao_preventiva_imediata || "Nenhuma ação preventiva sugerida."}</p></div><div className="risk-meta"><span>Metodologia</span><b>{risk.metodologia || "ISO 31000"}</b><span>Não conformidades analisadas</span><b>{risk.total_nao_conformidades_analisadas ?? 0}</b></div></Panel>
    </section>
    <Panel className="full-panel" title="Auditorias de origem" description="Registros enviados ao motor de risco transversal" icon={<FileClock size={16} />} action={<button className="panel-link" onClick={onView}>Abrir trilha de auditoria <ChevronRight size={14} /></button>}>
      {!risk.dados_origem?.length ? <EmptyState icon={<FileClock size={20} />} title="Nenhuma auditoria na análise" detail="A API não retornou não conformidades de origem." /> : <div className="audit-source-list">{risk.dados_origem.map((item) => <article key={item.id_auditoria}><span className={`audit-status ${item.status === "NAO_CONFORME" ? "nonconform" : ""}`}><AlertTriangle size={14} /></span><div><b>{item.item_controle}</b><small>{item.id_auditoria} · {item.setor}</small><p>{item.evidencia_descrita}</p></div><span className="status-pill open">{item.status === "NAO_CONFORME" ? "Não conforme" : item.status}</span></article>)}</div>}
    </Panel>
  </>;
}

function AuditPage({ entries, loading }: { entries: AuditEntry[]; loading: boolean }) {
  return <Panel className="full-panel" title="Trilha de auditoria" description="Eventos recebidos e transições de estado dos alertas" icon={<FileClock size={16} />}>
    {loading && entries.length === 0 ? <LoadingRows /> : entries.length === 0 ? <EmptyState icon={<FileClock size={20} />} title="A trilha está vazia" detail="Eventos e ações sobre alertas aparecerão aqui em ordem cronológica." /> :
      <div className="table-scroll"><table className="data-table audit-table"><thead><tr><th>Registro</th><th>Ator</th><th>Detalhe</th><th>Resultado</th><th>Data e hora</th></tr></thead><tbody>{entries.map((entry) => <tr key={`${entry.kind}-${entry.id}`}><td><span className={`audit-kind ${entry.kind.toLowerCase()}`}>{entry.kind === "EVENT" ? "Evento" : "Alerta"}</span><span className="event-label">{entry.action}</span></td><td className="identity-cell">{entry.actor}</td><td>{entry.detail}</td><td>{entry.outcome}</td><td className="date-cell">{formatDate(entry.createdAt)}</td></tr>)}</tbody></table></div>}
  </Panel>;
}

function EventModal({ onClose, onSubmit }: { onClose: () => void; onSubmit: (payload: Record<string, string>) => Promise<void> }) {
  const [eventType, setEventType] = useState("login.failure");
  const [actorEmail, setActorEmail] = useState("");
  const [sourceIp, setSourceIp] = useState("");
  const [sourceSystem, setSourceSystem] = useState("Sentinel Console");
  const [resource, setResource] = useState("");
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving(true);
    setError("");
    const outcome = eventType.endsWith(".failure") ? "failure" : "success";
    try {
      await onSubmit({ eventType, actorEmail, sourceIp, sourceSystem, outcome, ...(resource ? { resource } : {}) });
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Não foi possível registrar o evento.");
    } finally {
      setSaving(false);
    }
  }

  return <div className="modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}><section className="event-modal" role="dialog" aria-modal="true" aria-labelledby="modal-title">
    <div className="modal-heading"><div><span className="modal-icon"><Activity size={18} /></span><div><h2 id="modal-title">Registrar evento</h2><p>O evento será armazenado na trilha de segurança.</p></div></div><button className="icon-button" aria-label="Fechar" onClick={onClose}><X size={18} /></button></div>
    <form onSubmit={submit}><label>Tipo de evento<select value={eventType} onChange={(event) => setEventType(event.target.value)}><option value="login.failure">Falha de login</option><option value="login.success">Login autorizado</option><option value="mfa.failure">Falha de MFA</option><option value="privilege.change">Alteração de privilégio</option><option value="policy.change">Alteração de política</option><option value="sensitive.access">Acesso sensível</option></select></label>
      <div className="form-grid"><label>Identidade (e-mail)<input type="email" required maxLength={254} value={actorEmail} onChange={(event) => setActorEmail(event.target.value)} placeholder="analista@empresa.com" /></label><label>IP de origem<input required value={sourceIp} onChange={(event) => setSourceIp(event.target.value)} placeholder="203.0.113.10" /></label></div>
      <div className="form-grid"><label>Sistema de origem<input required maxLength={100} value={sourceSystem} onChange={(event) => setSourceSystem(event.target.value)} /></label><label>Recurso <span className="optional-label">opcional</span><input maxLength={200} value={resource} onChange={(event) => setResource(event.target.value)} placeholder="admin/roles" /></label></div>
      {error && <div className="form-error"><AlertTriangle size={15} />{error}</div>}<div className="modal-footer"><span><LockKeyhole size={13} /> Nunca inclua senhas ou tokens no evento.</span><button type="button" className="button button-secondary" onClick={onClose}>Cancelar</button><button type="submit" className="button button-primary" disabled={saving}>{saving ? "Registrando..." : "Salvar evento"}</button></div>
    </form>
  </section></div>;
}

function EmptyState({ icon, title, detail }: { icon: ReactNode; title: string; detail: string }) {
  return <div className="empty-state"><span>{icon}</span><b>{title}</b><p>{detail}</p></div>;
}

function LoadingRows() {
  return <div className="loading-rows" aria-label="Carregando dados"><i /><i /><i /></div>;
}

export default App;
