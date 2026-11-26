/**
 * «El embudo vivo» (react-three-fiber + drei). Se carga aparte (`lazy`) y solo si hay WebGL y nadie
 * pidió menos movimiento. Cada CVE con cambios hoy es una partícula que baja en espiral por el
 * embudo; las que acaban en A, B o C se encienden con el color de su nivel (tokens) y caen sobre
 * la columna de su tarjeta. Al pasar el ratón se ve la CVE. Las cifras son las de la API: aquí no se
 * calcula ninguna, solo se dibujan `data.particles` y `data.counts`.
 */
import { Html } from "@react-three/drei";
import { Canvas, useFrame, useThree, type ThreeEvent } from "@react-three/fiber";
import { useEffect, useLayoutEffect, useMemo, useRef, useState, type RefObject } from "react";
import { Color, Object3D, Sphere, Vector3, type InstancedMesh } from "three";
import { formatCount } from "@/components/magicui/number-ticker";
import { funnelLabel, LEVEL_COLUMN } from "@/components/funnel/geometry";
import { unitHash, type FunnelData, type FunnelParticle } from "@/lib/funnel";
import { ALERT_LEVELS, levelLabel, type Level } from "@/theme/tokens";

const TOP_Y = 2.0;
const THROAT_Y = -0.45;
const PAD_Y = -2.15;
const THROAT_R = 0.28;
const SPIRAL_S = 4.2;
const FALL_S = 1.1;

type Palette = Record<Level | "ring", Color>;

/** Resuelve una variable de `tokens.css` (oklch) a sRGB pintándola en un canvas 2D de 1×1. */
function cssColor(name: string): Color {
  const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const ctx = document.createElement("canvas").getContext("2d", { willReadFrequently: true });
  const out = new Color();
  if (!ctx || !value) return out;
  ctx.canvas.width = ctx.canvas.height = 1;
  ctx.fillStyle = "black";
  ctx.fillStyle = value;
  ctx.fillRect(0, 0, 1, 1);
  const [r, g, b] = ctx.getImageData(0, 0, 1, 1).data;
  return out.setRGB(r / 255, g / 255, b / 255, "srgb");
}

function readPalette(): Palette {
  return {
    A: cssColor("--level-a"),
    B: cssColor("--level-b"),
    C: cssColor("--level-c"),
    none: cssColor("--level-none"),
    ring: cssColor("--muted-foreground"),
  };
}

/** La paleta se vuelve a leer si cambia el tema (clase de `<html>`). */
function usePalette(): Palette {
  const [palette, setPalette] = useState<Palette>(readPalette);
  useEffect(() => {
    const mo = new MutationObserver(() => setPalette(readPalette()));
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });
    return () => mo.disconnect();
  }, []);
  return palette;
}

interface Seeded extends FunnelParticle {
  angle: number;
  offset: number;
  period: number;
  jx: number;
  jz: number;
}

function seed(p: FunnelParticle): Seeded {
  return {
    ...p,
    angle: unitHash(p.id, 1) * Math.PI * 2,
    offset: unitHash(p.id, 2),
    period: 6 + unitHash(p.id, 3) * 5,
    jx: unitHash(p.id, 4) * 2 - 1,
    jz: unitHash(p.id, 5) * 2 - 1,
  };
}

const ease = (t: number) => 1 - (1 - t) ** 2;

interface ParticlesProps {
  data: FunnelData;
  palette: Palette;
  /** Contenedor fijo de las etiquetas (`Html`): sin él, drei cambia de destino al conectar los eventos y pierde la primera. */
  overlay: RefObject<HTMLElement>;
}

function Particles({ data, palette, overlay }: ParticlesProps) {
  const mesh = useRef<InstancedMesh>(null);
  const seeded = useMemo(() => data.particles.map(seed), [data.particles]);
  const positions = useRef(new Float32Array(seeded.length * 3));
  const [hover, setHover] = useState<number | null>(null);
  const [hoverAt, setHoverAt] = useState<[number, number, number]>([0, 0, 0]);
  const width = useThree((s) => s.viewport.width);
  const topR = Math.min(width * 0.3, 3.2);
  const padX = (lv: Exclude<Level, "none">) => (LEVEL_COLUMN[lv] - 1) * (width / 3);
  const dummy = useMemo(() => new Object3D(), []);
  const tmp = useMemo(() => new Color(), []);

  useLayoutEffect(() => {
    const m = mesh.current;
    if (!m) return;
    // Las instancias se mueven: una esfera fija y amplia evita recalcular el volumen en cada rayo.
    m.boundingSphere = new Sphere(new Vector3(), 50);
    for (let i = 0; i < seeded.length; i++) m.setColorAt(i, palette.none);
    if (m.instanceColor) m.instanceColor.needsUpdate = true;
  }, [seeded, palette]);

  useFrame(({ clock }) => {
    const m = mesh.current;
    if (!m) return;
    const time = clock.getElapsedTime();
    const pos = positions.current;
    for (let i = 0; i < seeded.length; i++) {
      const p = seeded[i];
      let x: number;
      let y: number;
      let z: number;
      let scale = 1;
      if (p.level === "none") {
        const t = ((time / p.period + p.offset) % 1 + 1) % 1;
        const s = ease(Math.min(t / 0.8, 1));
        const r = topR + (THROAT_R - topR) * s;
        const a = p.angle + s * Math.PI * 3;
        x = Math.cos(a) * r;
        z = Math.sin(a) * r;
        y = TOP_Y + (THROAT_Y - TOP_Y) * s;
        if (t > 0.8) {
          const k = (t - 0.8) / 0.2;
          y -= k * 0.4;
          scale = 1 - k;
        }
        tmp.copy(palette.none);
      } else {
        const start = p.offset * 3;
        const t = Math.max(0, time - start);
        const target = padX(p.level);
        const restX = target + p.jx * 0.45;
        const restZ = p.jz * 0.35;
        if (t < SPIRAL_S) {
          const s = ease(t / SPIRAL_S);
          const r = topR + (THROAT_R - topR) * s;
          const a = p.angle + s * Math.PI * 3;
          x = Math.cos(a) * r;
          z = Math.sin(a) * r;
          y = TOP_Y + (THROAT_Y - TOP_Y) * s;
          tmp.copy(palette.none).lerp(palette[p.level], Math.max(0, (s - 0.7) / 0.3));
        } else if (t < SPIRAL_S + FALL_S) {
          const k = (t - SPIRAL_S) / FALL_S;
          x = restX * k;
          z = restZ * k;
          y = THROAT_Y + (PAD_Y - THROAT_Y) * k * k;
          tmp.copy(palette[p.level]);
        } else {
          x = restX;
          z = restZ;
          y = PAD_Y + 0.06 + Math.sin(time * 1.5 + p.angle) * 0.03;
          tmp.copy(palette[p.level]);
        }
        scale = 1.7;
      }
      if (hover === i) scale *= 1.6;
      pos[i * 3] = x;
      pos[i * 3 + 1] = y;
      pos[i * 3 + 2] = z;
      dummy.position.set(x, y, z);
      dummy.scale.setScalar(scale);
      dummy.updateMatrix();
      m.setMatrixAt(i, dummy.matrix);
      m.setColorAt(i, tmp);
    }
    m.instanceMatrix.needsUpdate = true;
    if (m.instanceColor) m.instanceColor.needsUpdate = true;
  });

  const onMove = (e: ThreeEvent<PointerEvent>) => {
    e.stopPropagation();
    const i = e.instanceId;
    if (i === undefined || i === hover) return;
    const pos = positions.current;
    setHover(i);
    setHoverAt([pos[i * 3], pos[i * 3 + 1] + 0.25, pos[i * 3 + 2]]);
  };

  const hovered = hover !== null ? seeded[hover] : undefined;
  return (
    <>
      <instancedMesh
        ref={mesh}
        args={[undefined, undefined, seeded.length]}
        onPointerMove={onMove}
        onPointerOut={() => setHover(null)}
      >
        <sphereGeometry args={[0.065, 10, 10]} />
        <meshBasicMaterial toneMapped={false} />
      </instancedMesh>
      {hovered ? (
        <Html
          position={hoverAt}
          portal={overlay}
          center
          style={{ pointerEvents: "none" }}
        >
          <div
            role="tooltip"
            data-testid="funnel-tooltip"
            className="whitespace-nowrap rounded-md border bg-popover px-2 py-1 font-mono text-xs text-popover-foreground shadow"
          >
            {hovered.id} · {levelLabel[hovered.level]}
          </div>
        </Html>
      ) : null}
      {ALERT_LEVELS.map((lv) => (
        <group key={lv} position={[padX(lv), PAD_Y, 0]}>
          <mesh rotation={[-Math.PI / 2, 0, 0]}>
            <circleGeometry args={[0.65, 40]} />
            <meshBasicMaterial color={palette[lv]} transparent opacity={0.3} toneMapped={false} />
          </mesh>
          <Html position={[0.95, 0.05, 0]} portal={overlay} center style={{ pointerEvents: "none" }}>
            <span
              data-testid={`funnel-pad-${lv}`}
              className="whitespace-nowrap rounded bg-background/80 px-1 font-mono text-xs text-foreground"
            >
              {lv} · {formatCount(data.counts[lv])}
            </span>
          </Html>
        </group>
      ))}
      <Rings topR={topR} color={palette.ring} />
    </>
  );
}

function Rings({ topR, color }: { topR: number; color: Color }) {
  const group = useRef<Object3D>(null);
  useFrame((_, dt) => {
    if (group.current) group.current.rotation.y += dt * 0.15;
  });
  const rings = [0, 0.2, 0.4, 0.6, 0.8, 1];
  return (
    <group ref={group}>
      {rings.map((s) => {
        const r = topR + (THROAT_R - topR) * ease(s);
        const y = TOP_Y + (THROAT_Y - TOP_Y) * s;
        return (
          <mesh key={s} position={[0, y, 0]} rotation={[Math.PI / 2, 0, 0]}>
            <torusGeometry args={[r, 0.008, 6, 96]} />
            <meshBasicMaterial color={color} transparent opacity={0.45} toneMapped={false} />
          </mesh>
        );
      })}
    </group>
  );
}

export default function FunnelScene({ data }: { data: FunnelData }) {
  const palette = usePalette();
  // El div existe antes que el Canvas y que sus hijos: `null!` solo hasta el primer montaje.
  const overlay = useRef<HTMLDivElement>(null!);
  return (
    <div data-testid="funnel-3d" role="img" aria-label={funnelLabel(data)} className="relative h-full w-full">
      <div ref={overlay} className="pointer-events-none absolute inset-0 z-10 overflow-hidden" />
      <Canvas
        dpr={[1, 1.75]}
        gl={{ antialias: true, alpha: true, powerPreference: "low-power" }}
        camera={{ position: [0, 1.5, 5.6], fov: 42 }}
        onCreated={({ camera }) => camera.lookAt(0, -0.15, 0)}
        aria-hidden="true"
      >
        <Particles data={data} palette={palette} overlay={overlay} />
      </Canvas>
    </div>
  );
}
