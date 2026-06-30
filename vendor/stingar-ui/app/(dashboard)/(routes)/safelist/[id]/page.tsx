"use client";

import { useState, useEffect } from "react";
import { usePageTitle } from "@/lib/hooks/use-page-title";
import { useRouter, useParams } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import NextLink from "next/link";
import { ArrowLeft } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export default function EditSafelistEntryPage() {
  const params = useParams();
  const id = typeof params?.id === "string" ? params.id : "";
  usePageTitle(`Safelist: Edit entry ${id ? `#${id}` : ""}`);
  const router = useRouter();

  const [cidr, setCidr] = useState("");
  const [label, setLabel] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(!!id);

  const validateCidr = (value: string): string | null => {
    if (!value.trim()) return "IP or CIDR is required.";
    const ipv4Cidr = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
    const ipv6Cidr = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(\/\d{1,3})?$/;
    if (ipv4Cidr.test(value.trim()) || ipv6Cidr.test(value.trim())) return null;
    return "Enter a valid IP address or CIDR (e.g. 10.0.0.0/8 or 192.168.1.1).";
  };

  useEffect(() => {
    if (!id) {
      setLoading(false);
      return;
    }
    // TODO: fetch entry by id from API
    setLoading(false);
  }, [id]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const err = validateCidr(cidr);
    setError(err ?? null);
    if (err) return;
    // TODO: call API when backend is ready
    router.push("/safelist");
  };

  if (loading) {
    return (
      <div className="flex flex-col gap-4 max-w-2xl">
        <NextLink href="/safelist">
          <Button variant="ghost" size="sm" className="gap-1">
            <ArrowLeft className="h-4 w-4" aria-hidden />
            Back to Safelist
          </Button>
        </NextLink>
        <p className="text-muted-foreground">Loading entry…</p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6 max-w-2xl">
      <NextLink href="/safelist">
        <Button variant="ghost" size="sm" className="gap-1">
          <ArrowLeft className="h-4 w-4" aria-hidden />
          Back to Safelist
        </Button>
      </NextLink>

      <h1 className="text-xl font-bold text-left">
        Safelist: Edit entry {id ? `#${id}` : ""}
      </h1>

      <form onSubmit={handleSubmit}>
        <Card>
          <CardHeader>
            <CardTitle>Edit safelist entry (never block)</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            {error && (
              <p className="text-sm text-destructive" role="alert">
                {error}
              </p>
            )}
            <div>
              <Label htmlFor="cidr">IP or CIDR *</Label>
              <Input
                id="cidr"
                value={cidr}
                onChange={(e) => {
                  setCidr(e.target.value);
                  setError(null);
                }}
                placeholder="e.g. 10.0.0.0/8 or 192.168.1.0/24"
                className="font-mono"
                aria-required="true"
                aria-invalid={!!error}
              />
            </div>
            <div>
              <Label htmlFor="label">Label (optional)</Label>
              <Input
                id="label"
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                placeholder="e.g. Trusted scanner"
              />
            </div>
            <div className="flex gap-2">
              <Button type="submit">Save</Button>
              <NextLink href="/safelist">
                <Button type="button" variant="outline">
                  Cancel
                </Button>
              </NextLink>
            </div>
          </CardContent>
        </Card>
      </form>
    </div>
  );
}
