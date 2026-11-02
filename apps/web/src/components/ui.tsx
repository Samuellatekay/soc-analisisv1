export const Level = ({ v }: { v?: string | null }) => <span className={`lv lv-${v || "none"}`}>{v ? ({ high: "Tinggi", medium: "Sedang", low: "Rendah" } as any)[v] : "–"}</span>;
export const Disp = ({ v }: { v: string }) => <span className={`dp dp-${v}`}>{({ retained: "dipertahankan", manual_review: "review manual", filtered: "difilter (noise)" } as any)[v] || v}</span>;
export const Mono = ({ children }: { children: any }) => <code className="mono">{children}</code>;
export const fmt = (iso: string) => iso.replace("T", " ").slice(0, 19);
export const Empty = ({ children }: { children: any }) => <p className="muted empty">{children}</p>;
