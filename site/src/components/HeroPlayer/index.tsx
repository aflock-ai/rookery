import React, {useEffect, useRef} from 'react';
import 'asciinema-player/dist/bundle/asciinema-player.css';
import styles from './styles.module.css';

// HeroPlayer replays a recorded terminal session (an asciinema .cast — real,
// selectable text, ~50 KB) instead of shipping a multi-hundred-KB GIF. The
// asciinema-player JS is loaded lazily on the client only (it touches the
// DOM, so it must not run during SSR). Under prefers-reduced-motion we don't
// autoplay — the player shows a static poster frame instead.
export default function HeroPlayer({src}: {src: string}): React.ReactElement {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let player: {dispose: () => void} | undefined;
    let disposed = false;

    import('asciinema-player').then((AsciinemaPlayer) => {
      if (disposed || !ref.current) return;
      const reduce =
        typeof window !== 'undefined' &&
        window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
      player = AsciinemaPlayer.create(src, ref.current, {
        autoPlay: !reduce,
        loop: false,
        controls: true,
        theme: 'dracula',
        fit: 'width',
        terminalFontSize: '14px',
        idleTimeLimit: 1.5,
        speed: 1.5,
        poster: 'npt:1:15', // a late frame: the verified chain + report
      });
    });

    return () => {
      disposed = true;
      player?.dispose();
    };
  }, [src]);

  return <div className={styles.heroPlayer} ref={ref} aria-label="Replay of a Claude Code session standing up an internal supply chain for LiteLLM with CI/lock — build, scan, verify, and report under eBPF tracing" />;
}
