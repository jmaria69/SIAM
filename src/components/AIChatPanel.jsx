import React, { useState } from 'react';

const API_BASE = 'http://localhost:8001';

const ROLES = [
  { value: 'direccion', label: 'Dirección' },
  { value: 'it_responsable', label: 'Responsable IT' },
  { value: 'analista', label: 'Analista' },
  { value: 'auditor', label: 'Auditor' },
  { value: 'admin', label: 'Administrador' },
  { value: 'superadmin', label: 'Superadministrador' },
];

export default function AIChatPanel({ incidentId = null }) {
  const [role, setRole] = useState('analista');
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);
  const [provider, setProvider] = useState(null);

  async function send() {
    if (!input.trim() || sending) return;
    const userMessage = { role: 'user', content: input };
    const history = messages;
    setMessages((prev) => [...prev, userMessage]);
    setInput('');
    setSending(true);
    try {
      const res = await fetch(`${API_BASE}/v1/ai/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: userMessage.content,
          user_role: role,
          incident_id: incidentId,
          history,
        }),
      });
      const data = await res.json();
      setProvider(data.proveedor_ia);
      setMessages((prev) => [...prev, { role: 'assistant', content: data.respuesta }]);
    } catch (err) {
      setMessages((prev) => [...prev, { role: 'assistant', content: 'Error al contactar con el motor de IA.' }]);
    } finally {
      setSending(false);
    }
  }

  return (
    <div className="bg-slate-950 text-slate-100 min-h-screen p-4 sm:p-6 font-sans flex flex-col">
      <header className="mb-4 border-b border-slate-800 pb-4 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <span className="text-blue-500">💬</span> Chat de IA — SIEM Security
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            {provider ? `Proveedor activo: ${provider}` : 'El nivel de detalle se adapta al rol seleccionado'}
          </p>
        </div>
        <select
          value={role}
          onChange={(e) => setRole(e.target.value)}
          className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-sm"
        >
          {ROLES.map((r) => (
            <option key={r.value} value={r.value}>
              {r.label}
            </option>
          ))}
        </select>
      </header>

      <div className="flex-1 bg-slate-900 border border-slate-800 rounded-xl p-4 overflow-y-auto space-y-3 mb-4 min-h-[300px]">
        {messages.length === 0 && (
          <p className="text-slate-500 italic text-sm">
            Prueba: "¿qué significa esta alerta?", "¿qué prioridad tiene?", "¿cómo reducir este riesgo?"
          </p>
        )}
        {messages.map((m, idx) => (
          <div key={idx} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
            <div
              className={`max-w-[75%] rounded-lg px-3 py-2 text-sm whitespace-pre-line ${
                m.role === 'user' ? 'bg-blue-600 text-white' : 'bg-slate-800 text-slate-200'
              }`}
            >
              {m.content}
            </div>
          </div>
        ))}
        {sending && <div className="text-slate-500 text-xs italic">Pensando...</div>}
      </div>

      <div className="flex gap-2">
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && send()}
          placeholder="Escribe tu pregunta..."
          className="flex-1 bg-slate-900 border border-slate-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-blue-500"
        />
        <button
          onClick={send}
          disabled={sending}
          className="bg-blue-600 hover:bg-blue-500 disabled:opacity-50 px-4 py-2 rounded text-sm font-semibold"
        >
          Enviar
        </button>
      </div>
    </div>
  );
}
