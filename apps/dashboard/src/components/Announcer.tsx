import { createContext, useCallback, useContext, useMemo, useState } from 'react';
import type { ReactNode } from 'react';

export type NoticeTone = 'success' | 'error';

interface Notice {
  id: number;
  message: string;
  tone: NoticeTone;
}

interface AnnouncerValue {
  notice: Notice | null;
  announce: (message: string, tone?: NoticeTone) => void;
  dismiss: () => void;
}

const AnnouncerContext = createContext<AnnouncerValue | null>(null);

/** Holds the latest action outcome so it can be shown and read out by assistive technology. */
export function AnnouncerProvider({ children }: { children: ReactNode }) {
  const [notice, setNotice] = useState<Notice | null>(null);

  const announce = useCallback((message: string, tone: NoticeTone = 'success') => {
    setNotice((previous) => ({ id: (previous?.id ?? 0) + 1, message, tone }));
  }, []);
  const dismiss = useCallback(() => setNotice(null), []);

  const value = useMemo(() => ({ notice, announce, dismiss }), [notice, announce, dismiss]);
  return <AnnouncerContext.Provider value={value}>{children}</AnnouncerContext.Provider>;
}

function useAnnouncer(): AnnouncerValue {
  const value = useContext(AnnouncerContext);
  if (value === null) throw new Error('AnnouncerProvider is missing');
  return value;
}

export function useAnnounce(): AnnouncerValue['announce'] {
  return useAnnouncer().announce;
}

/**
 * Live region for action outcomes. It stays mounted while empty so that screen readers
 * announce each new message as it arrives.
 */
export function NoticeRegion() {
  const { notice, dismiss } = useAnnouncer();
  return (
    <div className="notice-region" role="status" aria-live="polite">
      {notice !== null && (
        <div className={`notice notice-${notice.tone}`} key={notice.id}>
          <p>{notice.message}</p>
          <button type="button" className="button button-quiet" onClick={dismiss}>
            Dismiss
          </button>
        </div>
      )}
    </div>
  );
}
