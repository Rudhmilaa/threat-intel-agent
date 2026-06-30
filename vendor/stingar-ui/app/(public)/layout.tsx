export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <main id="main-content" className="w-full h-full">{children}</main>;
}
