import React, {useEffect, useRef, useState} from 'react';
import BrowserOnly from '@docusaurus/BrowserOnly';
import 'asciinema-player/dist/bundle/asciinema-player.css';
import styles from './styles.module.css';

type CastPlayerProps = {
  src: string;
  /** Accessible description of what the recording shows. */
  label: string;
  poster?: string;
  autoPlay?: boolean;
  loop?: boolean;
  controls?: boolean;
  /** SSR / no-JS fallback (e.g. a static <pre> for crawlers). */
  fallback?: React.ReactNode;
};

// CastPlayer replays a recorded terminal session (an asciinema .cast — real,
// selectable text) instead of a heavy GIF. asciinema-player touches the DOM, so
// it is loaded lazily on the client only and never during SSR.
//
// The player's native fullscreen button is hidden (its exit path mangles the
// surrounding page layout). In its place we offer an "expand" toggle that grows
// the player to the content width in a centered overlay — no Fullscreen API, so
// nothing to break on exit.
function Player({
  src,
  label,
  poster = 'npt:0:25',
  autoPlay = false,
  loop = false,
  controls = true,
}: CastPlayerProps): React.ReactElement {
  const ref = useRef<HTMLDivElement>(null);
  const [expanded, setExpanded] = useState(false);

  useEffect(() => {
    let player: {dispose: () => void} | undefined;
    let disposed = false;

    import('asciinema-player').then((AsciinemaPlayer) => {
      if (disposed || !ref.current) return;
      const reduce =
        typeof window !== 'undefined' &&
        window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
      player = AsciinemaPlayer.create(src, ref.current, {
        autoPlay: autoPlay && !reduce,
        loop,
        controls,
        theme: 'dracula',
        fit: 'width',
        terminalFontSize: '14px',
        idleTimeLimit: 1.5,
        speed: 1.5,
        poster,
      });
    });

    return () => {
      disposed = true;
      player?.dispose();
    };
    // `expanded` is a dependency on purpose: asciinema-player computes its font
    // size once for the container width and does not reliably shrink back when
    // the container collapses. Recreating it on expand/collapse guarantees it
    // always fits its current container — so collapsing returns to normal.
  }, [src, poster, autoPlay, loop, controls, expanded]);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setExpanded(false);
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  return (
    <>
      {expanded && (
        <div className={styles.backdrop} onClick={() => setExpanded(false)} />
      )}
      <div className={`${styles.castPlayer} ${expanded ? styles.expanded : ''}`}>
        <button
          type="button"
          className={styles.expandBtn}
          aria-label={expanded ? 'Collapse player' : 'Expand player to full width'}
          onClick={() => setExpanded((v) => !v)}>
          {expanded ? '🗙' : '⤢'}
        </button>
        <div ref={ref} aria-label={label} />
      </div>
    </>
  );
}

export default function CastPlayer(props: CastPlayerProps): React.ReactElement {
  return (
    <BrowserOnly
      fallback={
        props.fallback ?? (
          <pre className={styles.fallback} aria-label={props.label}>
            Loading recorded terminal session…
          </pre>
        )
      }>
      {() => <Player {...props} />}
    </BrowserOnly>
  );
}
