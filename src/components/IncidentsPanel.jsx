import React, { useEffect, useState } from 'react';

const API_BASE = 'http://localhost:8001';

const SEVERITY_STYLE = {
  critica: 'bg-rose-950 border-rose-500 text-rose-300',
  alta: 'bg-rose-900/40 border-rose-700 text-rose-300',
  media: 'bg-amber-900/30 border-amber-700 text-amber-300',
  baja: 'bg-slate-800 border-slate-700 text-slate-300',
  info: 'bg-slate-800 border-slate-700 text-slate-400',
};

const STATUS_LABEL = {
  abierto: 'Abierto',
  en_investigacion: 'En investigación',
  resuelto: 'Resuelto',
};

// El backend guarda datetime.utcnow() NAIVE (sin 'Z' ni offset): new Date()
// sobre ese string lo interpreta como hora LOCAL y todo sale desplazado.
// Se añade la 'Z' solo si el string no trae ya información de zona.
function parseUtc(iso) {
  if (!iso) return null;
  return new Date(/Z|[+-]\d\d:?\d\d$/.test(iso) ? iso : iso + 'Z');
}
function fmtDateTime(iso) {
  const d = parseUtc(iso);
  return d ? d.toLocaleString('es-ES', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—';
}
function fmtDuration(ms) {
  if (ms == null || isNaN(ms)) return '—';
  const s = Math.max(0, Math.floor(ms / 1000));
  const m = Math.floor(s / 60), h = Math.floor(m / 60), d = Math.floor(h / 24);
  if (d > 0) return `${d}d ${h % 24}h`;
  if (h > 0) return `${h}h ${m % 60}m`;
  if (m > 0) return `${m}m ${s % 60}s`;
  return `${s}s`;
}

export default function IncidentsPanel() {
  const [incidents, setIncidents] = useState([]);
  const [selected, setSelected] = useState(null);
  const [loading, setLoading] = useState(true);
  const [explaining, setExplaining] = useState(false);
  const [deleting, setDeleting] = useState(false);

  async function loadIncidents() {
    try {
      const res = await fetch(`${API_BASE}/v1/incidents`);
      if (res.ok) {
        const data = await res.json();
        setIncidents(data);
      }
    } catch (err) {
      console.error('Error cargando incidentes:', err);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadIncidents();
    const interval = setInterval(loadIncidents, 5000);
    return () => clearInterval(interval);
  }, []);

  async function updateStatus(id, status) {
    const res = await fetch(`${API_BASE}/v1/incidents/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status }),
    });
    // Sin esto, el panel de detalle se quedaba con el estado viejo hasta
    // re-seleccionar el incidente. El spread conserva los campos
    // solo-de-cliente (lastExplanation, aiProvider).
    if (res.ok) {
      const updated = await res.json();
      setSelected((prev) => (prev && prev.id === id ? { ...prev, ...updated } : prev));
    }
    await loadIncidents();
  }

  async function explain(id) {
    setExplaining(true);
    try {
      const res = await fetch(`${API_BASE}/v1/incidents/${id}/explain`, { method: 'POST' });
      // Un 500 pelado no es JSON: res.json() lanzaba y el usuario no veía
      // nada. Cualquier fallo acaba en explainError, visible en el panel.
      let data = null;
      try { data = await res.json(); } catch (e) { /* respuesta no-JSON */ }
      if (res.ok && data) {
        setSelected((prev) => (prev && prev.id === id ? { ...prev, lastExplanation: data.explicacion, aiProvider: data.proveedor_ia, explainError: null } : prev));
      } else {
        const detail = (data && data.detail) || `El servidor devolvió HTTP ${res.status}.`;
        setSelected((prev) => (prev && prev.id === id ? { ...prev, explainError: detail } : prev));
      }
    } catch (err) {
      setSelected((prev) => (prev && prev.id === id ? { ...prev, explainError: 'No se pudo contactar con el servidor: ' + err.message } : prev));
    } finally {
      setExplaining(false);
    }
  }

  async function removeIncident(id) {
    if (!window.confirm('¿Eliminar definitivamente este incidente resuelto? Esta acción no se puede deshacer.')) return;
    setDeleting(true);
    try {
      const res = await fetch(`${API_BASE}/v1/incidents/${id}`, { method: 'DELETE' });
      if (res.ok) {
        setSelected(null);
        await loadIncidents();
      } else {
        let data = null;
        try { data = await res.json(); } catch (e) { /* respuesta no-JSON */ }
        window.alert((data && data.detail) || `No se pudo eliminar el incidente (HTTP ${res.status}).`);
      }
    } finally {
      setDeleting(false);
    }
  }

  return (
    <div className="bg-slate-950 text-slate-100 min-h-screen p-4 sm:p-6 font-sans">
      <header className="mb-6 border-b border-slate-800 pb-4">
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <span className="text-rose-500">🛡️</span> Gestión de Incidentes
        </h1>
        <p className="text-sm text-slate-400 mt-1">Correlación automática de eventos por activo y ventana temporal</p>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-slate-900 rounded-xl border border-slate-800 shadow-lg overflow-hidden">
          {/* En móvil la tabla de 5 columnas se desplaza en horizontal en vez de aplastarse */}
          <div className="overflow-x-auto">
          <div className="min-w-[560px]">
          <div className="grid grid-cols-5 gap-2 text-xs font-bold text-slate-500 border-b border-slate-800 px-4 py-2">
            <div className="col-span-2">Incidente</div>
            <div>Severidad</div>
            <div>Estado</div>
            <div>Riesgo</div>
          </div>
          {loading ? (
            <div className="p-4 text-slate-500 italic">Cargando incidentes...</div>
          ) : incidents.length === 0 ? (
            <div className="p-4 text-slate-500 italic">Sin incidentes registrados todavía.</div>
          ) : (
            incidents.map((inc) => (
              <button
                key={inc.id}
                onClick={() => setSelected(inc)}
                className={`w-full text-left grid grid-cols-5 gap-2 px-4 py-3 border-b border-slate-900 hover:bg-slate-800/60 transition-colors ${
                  selected?.id === inc.id ? 'bg-slate-800/80' : ''
                }`}
              >
                <div className="col-span-2 truncate">
                  <div className="font-semibold truncate">{inc.title}</div>
                  <div className="text-xs text-slate-500">{inc.id} · {fmtDateTime(inc.created_at)}</div>
                </div>
                <div>
                  <span className={`px-2 py-0.5 rounded text-[10px] border ${SEVERITY_STYLE[inc.severity] || SEVERITY_STYLE.info}`}>
                    {inc.severity}
                  </span>
                </div>
                <div className="text-xs text-slate-400">
                  {STATUS_LABEL[inc.status] || inc.status}
                  {inc.resolved_at && (
                    <div className="text-[10px] text-emerald-500">⏱ {fmtDuration(parseUtc(inc.resolved_at) - parseUtc(inc.created_at))}</div>
                  )}
                </div>
                <div className="text-xs font-mono">{inc.risk_score}/100</div>
              </button>
            ))
          )}
          </div>
          </div>
        </div>

        <div className="bg-slate-900 rounded-xl border border-slate-800 shadow-lg p-4">
          {!selected ? (
            <p className="text-slate-500 italic text-sm">Selecciona un incidente para ver el detalle.</p>
          ) : (
            <div className="space-y-4">
              <div>
                <h2 className="text-lg font-semibold">{selected.title}</h2>
                <p className="text-xs text-slate-500">{selected.id}</p>
              </div>
              <p className="text-sm text-slate-300">{selected.description}</p>

              <div className="text-xs text-slate-400 space-y-0.5 border-t border-b border-slate-800 py-2">
                <div>📅 Creado: <span className="text-slate-300">{fmtDateTime(selected.created_at)}</span></div>
                {selected.resolved_at && (
                  <div>✅ Resuelto: <span className="text-slate-300">{fmtDateTime(selected.resolved_at)}</span></div>
                )}
                {selected.resolved_at && (
                  <div>⏱️ Tiempo de resolución: <span className="text-emerald-400 font-semibold">{fmtDuration(parseUtc(selected.resolved_at) - parseUtc(selected.created_at))}</span></div>
                )}
              </div>

              <div>
                <h3 className="text-xs font-bold text-slate-500 mb-1">Activos afectados</h3>
                <div className="flex flex-wrap gap-1">
                  {(selected.affected_assets || []).map((a) => (
                    <span key={a} className="text-[10px] bg-slate-800 border border-slate-700 rounded px-1.5 py-0.5">
                      {a}
                    </span>
                  ))}
                </div>
              </div>

              <div>
                <h3 className="text-xs font-bold text-slate-500 mb-1">Línea temporal</h3>
                <div className="space-y-1 max-h-40 overflow-y-auto font-mono text-xs">
                  {(selected.timeline || []).map((t, idx) => (
                    <div key={idx} className="border-b border-slate-900 pb-1">
                      <span className="text-slate-500">{parseUtc(t.timestamp).toLocaleTimeString()}</span>{' '}
                      <span className="text-blue-400">[{t.actor}]</span> {t.description}
                    </div>
                  ))}
                </div>
              </div>

              <div className="flex flex-wrap gap-2">
                {['abierto', 'en_investigacion', 'resuelto'].map((s) => (
                  <button
                    key={s}
                    onClick={() => updateStatus(selected.id, s)}
                    className={`text-xs px-2 py-1 rounded border ${
                      selected.status === s ? 'bg-blue-600 border-blue-500' : 'border-slate-700 hover:bg-slate-800'
                    }`}
                  >
                    {STATUS_LABEL[s]}
                  </button>
                ))}
              </div>

              <button
                onClick={() => explain(selected.id)}
                disabled={explaining}
                className="w-full text-xs bg-emerald-700 hover:bg-emerald-600 disabled:opacity-50 rounded px-3 py-2 font-semibold"
              >
                {explaining ? 'Consultando IA...' : '🤖 Explicar con IA'}
              </button>

              {selected.explainError && (
                <div className="bg-rose-950/60 border border-rose-800 rounded p-3 text-xs text-rose-300 whitespace-pre-line">
                  ⚠️ {selected.explainError}
                </div>
              )}

              {selected.lastExplanation && (
                <div className="bg-slate-950 border border-slate-800 rounded p-3 text-xs whitespace-pre-line">
                  <div className="text-slate-500 mb-1">Proveedor: {selected.aiProvider}</div>
                  {selected.lastExplanation}
                </div>
              )}

              {/* Siempre visible (deshabilitado si no está resuelto): oculto
                  del todo nadie descubría que la opción existía. */}
              <button
                onClick={() => removeIncident(selected.id)}
                disabled={deleting || selected.status !== 'resuelto'}
                title={selected.status !== 'resuelto' ? 'Marca el incidente como Resuelto para poder eliminarlo' : 'Eliminar definitivamente este incidente'}
                className="w-full text-xs bg-rose-800 hover:bg-rose-700 disabled:opacity-40 disabled:cursor-not-allowed rounded px-3 py-2 font-semibold"
              >
                {deleting ? 'Eliminando...' : '🗑️ Eliminar incidente'}
              </button>
              {selected.status !== 'resuelto' && (
                <p className="text-[10px] text-slate-500 text-center -mt-2">Solo se pueden eliminar incidentes resueltos.</p>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
