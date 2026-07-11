import { redirect } from 'next/navigation';

// Security is the default landing page (mirrors the Vite dashboard's index route).
export default function Home() {
  redirect('/security');
}
