import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { AlertTriangle, BrainCircuit, CheckCircle2, ClipboardList, LoaderCircle, RefreshCw, ShieldCheck, Sparkles } from 'lucide-react';
import { ApiRequestError } from '../api/httpClient';
import { getAIStatus, requestAIAssistance, type AIAssistResponse, type AIStatus, type AITask } from '../api/aiService';
import { StatusPill } from '../components/StatusPill';

const taskOptions: Array<{ value: AITask; label: string; description: string }> = [
  { value: 'process_review', label: 'Revisión de procesos', description: 'Evalúa inventario, estados, hallazgos y módulos pendientes usando datos reales.' },
  { value: 'finding_triage', label: 'Priorizar hallazgos', description: 'Ordena hasta 50 hallazgos abiertos dentro de tu espacio autorizado.' },
  { value: 'remediation_plan', label: 'Plan de remediación', description: 'Propone una secuencia de corrección y validación basada en los hallazgos existentes.' },
  { value: 'audit_summary', label: 'Resumen de auditoría', description: 'Resume la auditoría más reciente o una auditoría indicada por su identificador.' },
  { value: 'general', label: 'Consultar al copiloto', description: 'Pide orientación sobre uso seguro y mejora operativa de WebGuard.' },
];

export function AIAssistantPage() {
  const [status, setStatus] = useState<AIStatus | null>(null);
  const [task, setTask] = useState<AITask>('process_review');
  const [question, setQuestion] = useState('');
  const [auditId, setAuditId] = useState('');
  const [result, setResult] = useState<AIAssistResponse | null>(null);
  const [loadingStatus, setLoadingStatus] = useState(true);
  const [working, setWorking] = useState(false);
  const [error, setError] = useState('');

  const refreshStatus = useCallback(async () => {
    setLoadingStatus(true);
    try { setStatus(await getAIStatus()); setError(''); }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'No se pudo consultar el estado de IA.'); }
    finally { setLoadingStatus(false); }
  }, []);

  useEffect(() => { void refreshStatus(); }, [refreshStatus]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setWorking(true);
    setError('');
    setResult(null);
    try {
      setResult(await requestAIAssistance({
        task,
        ...(question.trim() ? { question: question.trim() } : {}),
        ...(task === 'audit_summary' && auditId.trim() ? { audit_id: auditId.trim() } : {}),
      }));
    } catch (cause) {
      setError(cause instanceof ApiRequestError ? cause.message : cause instanceof Error ? cause.message : 'Falló el análisis.');
    } finally { setWorking(false); }
  }

  const selectedTask = taskOptions.find((option) => option.value === task)!;

  return (
    <div className="ai-page">
      <section className="ai-hero">
        <div className="ai-hero__symbol"><BrainCircuit size={26} aria-hidden="true" /></div>
        <div className="ai-hero__copy">
          <span className="eyebrow">WEBGUARD INTELLIGENCE</span>
          <h2>AI Copilot</h2>
          <p>Convierte los datos existentes en prioridades, resúmenes y planes de mejora. Las recomendaciones requieren revisión humana.</p>
        </div>
        <div className="ai-hero__status">
          <StatusPill status={loadingStatus ? 'Consultando IA' : status?.configured ? 'Modelo configurado' : status ? 'Modo local' : 'Sin conexión'} />
          <button className="secondary-button" type="button" onClick={() => void refreshStatus()} disabled={loadingStatus}>
            <RefreshCw size={14} aria-hidden="true" /> Actualizar
          </button>
        </div>
      </section>

      {status && <section className={`ai-mode-banner${status.configured ? ' ai-mode-banner--remote' : ''}`}>
        {status.configured ? <CheckCircle2 size={18} aria-hidden="true" /> : <ShieldCheck size={18} aria-hidden="true" />}
        <div><strong>{status.configured ? `${status.provider} · ${status.model ?? 'modelo configurado'}` : 'Asistente local activo'}</strong>
          <p>{status.privacy_note}</p></div>
      </section>}

      <div className="ai-workspace">
        <section className="panel ai-form-panel">
          <div className="panel__heading"><div><h2>¿Qué quieres mejorar?</h2><p>Elige un proceso y analiza información que tu cuenta tiene permitido consultar.</p></div><span className="panel__heading-icon"><Sparkles size={18} /></span></div>
          <form onSubmit={handleSubmit} className="ai-form">
            <label htmlFor="ai-task">Proceso</label>
            <select id="ai-task" value={task} onChange={(event) => setTask(event.target.value as AITask)}>
              {taskOptions.map((option) => <option value={option.value} key={option.value}>{option.label}</option>)}
            </select>
            <p className="ai-task-description">{selectedTask.description}</p>

            {task === 'audit_summary' && <>
              <label htmlFor="ai-audit-id">ID de auditoría <span>(opcional)</span></label>
              <input id="ai-audit-id" value={auditId} onChange={(event) => setAuditId(event.target.value)} maxLength={36} placeholder="Vacío = auditoría más reciente" />
            </>}

            <label htmlFor="ai-question">Instrucciones adicionales <span>(opcional)</span></label>
            <textarea id="ai-question" value={question} onChange={(event) => setQuestion(event.target.value)} rows={4} maxLength={3000}
              placeholder={task === 'general' ? 'Ej. ¿Cómo puedo organizar la revisión semanal de hallazgos?' : 'Ej. Enfoca las recomendaciones en las acciones de mayor prioridad…'} />
            <div className="ai-form-footer"><span>{question.length}/3000 caracteres</span>
              <button type="submit" className="primary-button" disabled={working || loadingStatus || !status}>
                {working ? <><LoaderCircle className="spin" size={16} /> Analizando…</> : <><Sparkles size={16} /> Generar recomendaciones</>}
              </button>
            </div>
          </form>
          <div className="ai-guardrail"><ShieldCheck size={16} /><p>El copiloto no ejecuta escaneos, no modifica objetivos ni cambia permisos. Nunca envíes contraseñas, tokens o datos personales en las instrucciones.</p></div>
        </section>

        <section className="panel ai-result-panel" aria-live="polite">
          <div className="panel__heading"><div><h2>Resultado del análisis</h2><p>Recomendaciones con origen y alcance identificables.</p></div><span className="panel__heading-icon"><ClipboardList size={18} /></span></div>
          {working ? <div className="ai-placeholder"><LoaderCircle className="spin" size={24} /><strong>Analizando información autorizada</strong><p>No se están ejecutando pruebas de seguridad ni se están enviando trabajos al escáner.</p></div>
            : error ? <div className="ai-error"><AlertTriangle size={20} /><strong>No se pudo completar la solicitud</strong><p>{error}</p><small>Comprueba que el backend esté en ejecución y vuelve a intentarlo.</small></div>
              : result ? <div className="ai-result">
                <div className="ai-result__meta"><StatusPill status={result.mode === 'remote_model' ? 'Modelo generativo' : 'Reglas locales'} /><span>{new Date(result.generated_at).toLocaleString()}</span></div>
                <div className="ai-result__body">{result.answer}</div>
                <div className="ai-result__disclaimer"><AlertTriangle size={15} /><span>{result.disclaimer}</span></div>
              </div>
                : <div className="ai-placeholder"><div className="ai-placeholder__symbol"><Sparkles size={24} /></div><strong>Tu siguiente mejora empieza aquí</strong><p>Ejecuta una revisión para ver un análisis basado en la base de datos. El modo local no requiere una clave externa.</p></div>}
        </section>
      </div>

      <section className="ai-capabilities">
        {taskOptions.slice(0, 4).map((option, index) => <article className="ai-capability" key={option.value}>
          <span className={`ai-capability__number ai-capability__number--${index}`}>0{index + 1}</span><div><h3>{option.label}</h3><p>{option.description}</p></div>
        </article>)}
      </section>
      {!status?.configured && <p className="ai-setup-note"><ShieldCheck size={15} /> Para habilitar respuestas generativas con Groq, configura <code>WEBGUARD_AI_API_KEY</code>, <code>WEBGUARD_AI_MODEL</code> y <code>WEBGUARD_AI_BASE_URL</code> en el backend. La clave nunca se guarda en el frontend.</p>}
    </div>
  );
}
