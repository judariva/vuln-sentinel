/**
 * «El embudo vivo» (react-three-fiber + drei). Se carga aparte (`lazy`) y solo si hay WebGL y nadie
 * pidió menos movimiento. Las cifras son las de la API: aquí no se calcula ninguna, solo se dibujan
 * `data.particles`.
 *
 * Dirección de arte (T8c):
 * - todas las CVE del día entran por arriba, escalonadas, y bajan en espiral por el embudo;
 * - las que no tienen nivel se apagan al salir por la garganta y se quedan en el fondo como polvo;
 * - las que acaban en A, B o C se encienden con el color de su nivel, con brillo (sprite aditivo:
 *   sin posproceso, que no cabía en el presupuesto ni trata bien el lienzo transparente), y caen
 *   sobre la plataforma de su tarjeta;
 * - el embudo tiene superficie (malla translúcida y líneas), hay niebla con el color de la tarjeta
 *   y la cámara gira despacio;
 * - las etiquetas de los destinos están fuera, en HTML (`FunnelLabels`); aquí solo queda la de la
 *   CVE bajo el ratón.
 */
import { Html } from "@react-three/drei";
import { Canvas, useFrame, useThree, type ThreeEvent } from "@react-three/fiber";
import { useEffect, useLayoutEffect, useMemo, useRef, useState, type RefObject } from "react";
import {
  AdditiveBlending,
  BufferAttribute,
  BufferGeometry,
  CanvasTexture,
  Color,
  DoubleSide,
  LatheGeometry,
  NormalBlending,
  Object3D,
  Sphere,
  Vector2,
  Vector3,
  type Group,
  type InstancedMesh,
} from "three";
import { funnelLabel, LEVEL_COLUMN } from "@/components/funnel/geometry";
import { unitHash, type FunnelData, type FunnelParticle } from "@/lib/funnel";
import { ALERT_LEVELS, levelLabel, type Level } from "@/theme/tokens";

const TOP_Y = 1.75;
const THROAT_Y = -0.65;
const PAD_Y = -2.05;
const DUST_Y = -2.35;
const THROAT_R = 0.2;
/** Ventana en la que entran las CVE sin nivel y las alertas (segundos desde que se monta). */
const ENTRY_NONE_S = 10;
const ENTRY_ALERT_FROM = 1.5;
const ENTRY_ALERT_S = 6;
const FALL_S = 1.1;
const DUST_S = 1.8;
const CAM_R = 7.4;
const CAM_Y = 1.7;
const LOOK_Y = -0.2;

type Palette = Record<Level | "ring" | "bg", Color> & { dark: boolean };

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
    bg: cssColor("--card"),
    dark: document.documentElement.classList.contains("dark"),
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

/**
 * Sprite de brillo: una máscara radial de alfa (sin ficheros ni librerías). No lleva color: el del
 * nivel lo pone cada punto (`vertexColors`) o el material.
 */
function glowTexture(): CanvasTexture {
  const size = 64;
  const canvas = document.createElement("canvas");
  canvas.width = canvas.height = size;
  const ctx = canvas.getContext("2d");
  if (ctx) {
    const img = ctx.createImageData(size, size);
    for (let py = 0; py < size; py++) {
      for (let px = 0; px < size; px++) {
        const d = Math.hypot(px + 0.5 - size / 2, py + 0.5 - size / 2) / (size / 2);
        // Núcleo intenso y halo que cae rápido hasta 0 en el borde.
        const a = d >= 1 ? 0 : Math.min(1, Math.exp(-d * d * 30) + (1 - d) ** 2.5 * 0.5);
        const o = (py * size + px) * 4;
        img.data[o] = img.data[o + 1] = img.data[o + 2] = 255;
        img.data[o + 3] = Math.round(a * 255);
      }
    }
    ctx.putImageData(img, 0, 0);
  }
  return new CanvasTexture(canvas);
}

/** Perfil del embudo: radio a la altura relativa `s` (0 arriba, 1 en la garganta). Bocina. */
function radiusAt(s: number, topR: number): number {
  return THROAT_R + (topR - THROAT_R) * (1 - s) ** 1.8;
}

interface Seeded extends FunnelParticle {
  angle: number;
  enter: number;
  spiral: number;
  jx: number;
  jz: number;
  dustX: number;
  dustZ: number;
}

function seed(p: FunnelParticle): Seeded {
  const alert = p.level !== "none";
  return {
    ...p,
    angle: unitHash(p.id, 1) * Math.PI * 2,
    enter: alert ? ENTRY_ALERT_FROM + unitHash(p.id, 2) * ENTRY_ALERT_S : unitHash(p.id, 2) * ENTRY_NONE_S,
    spiral: 3.6 + unitHash(p.id, 3) * 1.6,
    jx: unitHash(p.id, 4) * 2 - 1,
    jz: unitHash(p.id, 5) * 2 - 1,
    dustX: unitHash(p.id, 6) * 2 - 1,
    dustZ: unitHash(p.id, 7),
  };
}

const ease = (t: number) => 1 - (1 - t) ** 2;
const clamp01 = (t: number) => Math.min(1, Math.max(0, t));

interface ParticlesProps {
  data: FunnelData;
  palette: Palette;
  /** Contenedor fijo de la etiqueta (`Html`): sin él, drei cambia de destino al conectar los eventos y pierde la primera. */
  overlay: RefObject<HTMLElement>;
}

function Particles({ data, palette, overlay }: ParticlesProps) {
  const mesh = useRef<InstancedMesh>(null);
  const seeded = useMemo(() => data.particles.map(seed), [data.particles]);
  const alertIdx = useMemo(
    () => seeded.flatMap((p, i) => (p.level === "none" ? [] : [i])),
    [seeded],
  );
  const positions = useRef(new Float32Array(seeded.length * 3));
  const t0 = useRef<number | null>(null);
  const glowGeo = useMemo(() => {
    const g = new BufferGeometry();
    g.setAttribute("position", new BufferAttribute(new Float32Array(alertIdx.length * 3), 3));
    // RGBA: el brillo se apaga por alfa. Apagarlo a negro dejaba una mancha oscura, porque el lienzo
    // es transparente y la página compone ese negro con su alfa.
    g.setAttribute("color", new BufferAttribute(new Float32Array(alertIdx.length * 4), 4));
    // Los puntos se mueven: volumen fijo y amplio, como las instancias.
    g.boundingSphere = new Sphere(new Vector3(), 50);
    return g;
  }, [alertIdx]);
  const sprite = useMemo(() => glowTexture(), []);
  useEffect(() => () => glowGeo.dispose(), [glowGeo]);
  useEffect(() => () => sprite.dispose(), [sprite]);

  const [hover, setHover] = useState<number | null>(null);
  const [hoverAt, setHoverAt] = useState<[number, number, number]>([0, 0, 0]);
  const width = useThree((s) => s.viewport.width);
  const topR = topRadius(width);
  const padX = (lv: Exclude<Level, "none">) => (LEVEL_COLUMN[lv] - 1) * (width / 3);
  const dummy = useMemo(() => new Object3D(), []);
  const tmp = useMemo(() => new Color(), []);
  // Polvo: el gris de «sin nivel» medio apagado hacia el fondo de la tarjeta.
  const dust = useMemo(() => palette.none.clone().lerp(palette.bg, 0.55), [palette]);

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
    // El tiempo cuenta desde el primer fotograma de las partículas.
    t0.current ??= clock.getElapsedTime();
    const time = clock.getElapsedTime() - t0.current;
    const pos = positions.current;
    const gPos = glowGeo.getAttribute("position") as BufferAttribute;
    const gCol = glowGeo.getAttribute("color") as BufferAttribute;
    let g = 0;
    for (let i = 0; i < seeded.length; i++) {
      const p = seeded[i];
      const t = time - p.enter;
      let x = 0;
      let y = TOP_Y + 0.6;
      let z = 0;
      let scale = 0;
      let lit = 0;
      if (t >= 0 && t < p.spiral) {
        // Espiral: entra por el borde de arriba y baja hasta la garganta.
        const s = ease(t / p.spiral);
        const r = radiusAt(s, topR);
        const a = p.angle + s * Math.PI * 3.5;
        x = Math.cos(a) * r;
        z = Math.sin(a) * r;
        y = TOP_Y + (THROAT_Y - TOP_Y) * s;
        scale = Math.min(1, t * 3);
        if (p.level === "none") {
          tmp.copy(palette.none);
        } else {
          lit = clamp01((s - 0.55) / 0.45);
          tmp.copy(palette.none).lerp(palette[p.level], lit);
        }
      } else if (t >= p.spiral) {
        const k = t - p.spiral;
        if (p.level === "none") {
          // Se apaga y se posa en el fondo, repartida a lo ancho y hacia atrás.
          const d = ease(clamp01(k / DUST_S));
          const dx = p.dustX * width * 0.47;
          const dz = -0.4 - p.dustZ * 2.6;
          x = dx * d;
          z = dz * d;
          y = THROAT_Y + (DUST_Y - THROAT_Y) * d + Math.sin(time * 0.6 + p.angle) * 0.02 * d;
          scale = 1 - 0.45 * d;
          tmp.copy(palette.none).lerp(dust, d);
        } else {
          const target = padX(p.level);
          const restX = target + p.jx * 0.5;
          const restZ = p.jz * 0.4;
          lit = 1;
          scale = 1.8;
          tmp.copy(palette[p.level]);
          if (k < FALL_S) {
            const f = k / FALL_S;
            x = restX * ease(f);
            z = restZ * f;
            y = THROAT_Y + (PAD_Y - THROAT_Y) * f * f;
          } else {
            x = restX;
            z = restZ;
            y = PAD_Y + 0.08 + Math.sin(time * 1.5 + p.angle) * 0.04;
          }
        }
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
      if (p.level !== "none") {
        gPos.setXYZ(g, x, y, z);
        // El brillo late despacio una vez encendida.
        const pulse = lit * (0.85 + 0.15 * Math.sin(time * 2.2 + p.angle));
        const c = palette[p.level];
        gCol.setXYZW(g, c.r, c.g, c.b, pulse);
        g++;
      }
    }
    m.instanceMatrix.needsUpdate = true;
    if (m.instanceColor) m.instanceColor.needsUpdate = true;
    gPos.needsUpdate = true;
    gCol.needsUpdate = true;
  });

  const onMove = (e: ThreeEvent<PointerEvent>) => {
    e.stopPropagation();
    const i = e.instanceId;
    if (i === undefined || i === hover) return;
    const pos = positions.current;
    setHover(i);
    setHoverAt([pos[i * 3], pos[i * 3 + 1] + 0.3, pos[i * 3 + 2]]);
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
        <sphereGeometry args={[0.045, 10, 10]} />
        <meshBasicMaterial toneMapped={false} />
      </instancedMesh>
      <points geometry={glowGeo} raycast={() => null}>
        <pointsMaterial
          map={sprite}
          size={palette.dark ? 3.4 : 2.4}
          vertexColors
          transparent
          depthWrite={false}
          blending={palette.dark ? AdditiveBlending : NormalBlending}
          opacity={palette.dark ? 1 : 0.6}
          toneMapped={false}
        />
      </points>
      {hovered ? (
        <Html position={hoverAt} portal={overlay} center style={{ pointerEvents: "none" }}>
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
        <Pad key={lv} x={padX(lv)} color={palette[lv]} sprite={sprite} dark={palette.dark} />
      ))}
    </>
  );
}

/** Radio de la boca del embudo según el ancho visible (lo comparten el embudo y las partículas). */
function topRadius(width: number): number {
  return Math.min(width * 0.33, 4.6);
}

function FunnelShape({ color }: { color: Color }) {
  const width = useThree((s) => s.viewport.width);
  return <Funnel topR={topRadius(width)} color={color} />;
}

/** Plataforma de un nivel: disco con halo y aro, donde se posan sus alertas. */
function Pad({ x, color, sprite, dark }: { x: number; color: Color; sprite: CanvasTexture; dark: boolean }) {
  return (
    <group position={[x, PAD_Y, 0]} rotation={[-Math.PI / 2, 0, 0]}>
      <mesh raycast={() => null}>
        <planeGeometry args={[2.4, 2.4]} />
        <meshBasicMaterial
          map={sprite}
          color={color}
          transparent
          opacity={dark ? 0.55 : 0.4}
          depthWrite={false}
          blending={dark ? AdditiveBlending : NormalBlending}
          toneMapped={false}
        />
      </mesh>
      <mesh raycast={() => null}>
        <ringGeometry args={[0.66, 0.7, 64]} />
        <meshBasicMaterial color={color} transparent opacity={0.8} side={DoubleSide} toneMapped={false} />
      </mesh>
    </group>
  );
}

/** Embudo con superficie: malla de revolución translúcida, anillos y meridianos. Gira despacio. */
function Funnel({ topR, color }: { topR: number; color: Color }) {
  const group = useRef<Group>(null);
  const { surface, lines } = useMemo(() => {
    const STEPS = 28;
    const profile: Vector2[] = [];
    for (let i = 0; i <= STEPS; i++) {
      const s = i / STEPS;
      profile.push(new Vector2(radiusAt(s, topR), TOP_Y + (THROAT_Y - TOP_Y) * s));
    }
    const surface = new LatheGeometry(profile, 72);
    // Líneas: 7 anillos y 28 meridianos en una sola geometría de segmentos.
    const pts: number[] = [];
    const SEG = 96;
    for (const s of [0, 0.12, 0.26, 0.42, 0.6, 0.8, 1]) {
      const r = radiusAt(s, topR);
      const y = TOP_Y + (THROAT_Y - TOP_Y) * s;
      for (let j = 0; j < SEG; j++) {
        const a0 = (j / SEG) * Math.PI * 2;
        const a1 = ((j + 1) / SEG) * Math.PI * 2;
        pts.push(Math.cos(a0) * r, y, Math.sin(a0) * r, Math.cos(a1) * r, y, Math.sin(a1) * r);
      }
    }
    const MER = 28;
    for (let j = 0; j < MER; j++) {
      const a = (j / MER) * Math.PI * 2;
      for (let i = 0; i < STEPS; i++) {
        const p0 = profile[i];
        const p1 = profile[i + 1];
        pts.push(Math.cos(a) * p0.x, p0.y, Math.sin(a) * p0.x, Math.cos(a) * p1.x, p1.y, Math.sin(a) * p1.x);
      }
    }
    const lines = new BufferGeometry();
    lines.setAttribute("position", new BufferAttribute(new Float32Array(pts), 3));
    return { surface, lines };
  }, [topR]);
  useEffect(
    () => () => {
      surface.dispose();
      lines.dispose();
    },
    [surface, lines],
  );
  useFrame((_, dt) => {
    if (group.current) group.current.rotation.y += dt * 0.12;
  });
  return (
    <group ref={group}>
      <mesh geometry={surface} raycast={() => null}>
        <meshBasicMaterial color={color} transparent opacity={0.07} side={DoubleSide} depthWrite={false} toneMapped={false} />
      </mesh>
      <lineSegments geometry={lines} raycast={() => null}>
        <lineBasicMaterial color={color} transparent opacity={0.28} depthWrite={false} toneMapped={false} />
      </lineSegments>
    </group>
  );
}

/** Giro lento de la cámara (vaivén corto: las plataformas siguen sobre su etiqueta HTML). */
function CameraDrift() {
  useFrame(({ camera, clock }) => {
    const a = Math.sin(clock.getElapsedTime() * 0.09) * 0.2;
    camera.position.set(Math.sin(a) * CAM_R, CAM_Y, Math.cos(a) * CAM_R);
    camera.lookAt(0, LOOK_Y, 0);
  });
  return null;
}

/** Niebla con el color de la tarjeta: lo del fondo (el polvo, la cara de atrás) se difumina. */
function Fog({ color }: { color: Color }) {
  return <fog attach="fog" args={[color, CAM_R - 0.5, CAM_R + 5]} />;
}

export default function FunnelScene({ data }: { data: FunnelData }) {
  const palette = usePalette();
  // El div existe antes que el Canvas y que sus hijos: `null!` solo hasta el primer montaje.
  const overlay = useRef<HTMLDivElement>(null!);
  return (
    <div data-testid="funnel-3d" role="img" aria-label={funnelLabel(data)} className="relative h-full w-full">
      <div ref={overlay} className="pointer-events-none absolute inset-0 z-10 overflow-hidden" />
      <Canvas
        // Sin MSAA y con densidad de píxel acotada: el raster es lo que más cuesta en cada fotograma
        // (medido con Lighthouse en T8c) y las partículas con brillo no lo necesitan.
        dpr={[1, 1.25]}
        gl={{ antialias: false, alpha: true, powerPreference: "low-power" }}
        camera={{ position: [0, CAM_Y, CAM_R], fov: 40 }}
        onCreated={({ camera }) => camera.lookAt(0, LOOK_Y, 0)}
        aria-hidden="true"
      >
        <Fog color={palette.bg} />
        <CameraDrift />
        <FunnelShape color={palette.ring} />
        <Particles data={data} palette={palette} overlay={overlay} />
      </Canvas>
    </div>
  );
}
