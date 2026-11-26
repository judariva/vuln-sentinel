import { Link } from "react-router";

export function NotFoundPage() {
  return (
    <section className="space-y-2">
      <h1 className="text-2xl font-semibold">Página no encontrada</h1>
      <Link to="/" className="underline underline-offset-4">
        Volver a Hoy
      </Link>
    </section>
  );
}
