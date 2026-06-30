"use client";

import { useState } from "react";
import { Button, Alert } from "@mui/material";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import { HoneypotRequestCreate, IPProtocol, RequestPriority } from "@/models/hp-request";
import { toast } from "sonner";
import { AlertCircle } from "lucide-react";

interface HoneypotRequestFormProps {
  onSuccess?: () => void;
  onCancel?: () => void;
}

export function HoneypotRequestForm({ onSuccess, onCancel }: HoneypotRequestFormProps) {
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [formData, setFormData] = useState<Partial<HoneypotRequestCreate>>({
    title: "",
    description: "",
    priority: "medium",
    requiredPorts: [],
    supportedProtocols: [],
    ipProtocolSupport: [],
    cves: [],
    tags: [],
  });

  const [portInput, setPortInput] = useState("");
  const [protocolInput, setProtocolInput] = useState("");
  const [cveInput, setCveInput] = useState("");
  const [fieldErrors, setFieldErrors] = useState<{
    title?: string;
    description?: string;
    requesterName?: string;
    requesterEmail?: string;
    requesterOrganization?: string;
    cve?: string;
  }>({});

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setFieldErrors({});

    try {
      const errors: typeof fieldErrors = {};

      // Validate required fields
      if (!formData.title || !formData.description) {
        if (!formData.title?.trim()) errors.title = "Title is required";
        if (!formData.description?.trim()) errors.description = "Description is required";
      }

      // Validate requester information (required fields)
      if (!formData.requesterName || formData.requesterName.trim().length === 0) {
        errors.requesterName = "Your name is required";
      }

      if (!formData.requesterEmail || formData.requesterEmail.trim().length === 0) {
        errors.requesterEmail = "Your email address is required";
      } else {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(formData.requesterEmail)) {
          errors.requesterEmail = "Please enter a valid email address";
        }
      }

      if (!formData.requesterOrganization || formData.requesterOrganization.trim().length === 0) {
        errors.requesterOrganization = "Organization is required";
      }

      if (Object.keys(errors).length > 0) {
        setFieldErrors(errors);
        setIsSubmitting(false);
        return;
      }

      const requestData: HoneypotRequestCreate = {
        title: formData.title!,
        description: formData.description!,
        requesterName: formData.requesterName!,
        requesterEmail: formData.requesterEmail!,
        requesterOrganization: formData.requesterOrganization!,
        category: formData.category,
        priority: formData.priority || "medium",
        requiredPorts: formData.requiredPorts || [],
        supportedProtocols: formData.supportedProtocols || [],
        ipProtocolSupport: formData.ipProtocolSupport || [],
        cves: formData.cves || [],
        additionalRequirements: formData.additionalRequirements,
        tags: formData.tags || [],
        useCases: formData.useCases,
        expectedBehavior: formData.expectedBehavior,
        securityConsiderations: formData.securityConsiderations,
      };

      // Call Next.js API route instead of direct API call to avoid CORS issues
      const response = await fetch('/api/store/requests', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestData),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ error: 'Failed to submit request' }));
        throw new Error(errorData.error || `HTTP ${response.status}: ${response.statusText}`);
      }

      const result = await response.json();
      toast.success("Honeypot request submitted successfully!");

      if (onSuccess) {
        onSuccess();
      }
    } catch (error: any) {
      console.error("Error submitting request:", error);
      toast.error(error.message || "Failed to submit request");
    } finally {
      setIsSubmitting(false);
    }
  };

  const addPort = () => {
    const port = parseInt(portInput);
    if (port && port >= 1 && port <= 65535) {
      setFormData({
        ...formData,
        requiredPorts: [...(formData.requiredPorts || []), port].filter((p, i, arr) => arr.indexOf(p) === i),
      });
      setPortInput("");
    }
  };

  const removePort = (port: number) => {
    setFormData({
      ...formData,
      requiredPorts: (formData.requiredPorts || []).filter((p) => p !== port),
    });
  };

  const addProtocol = () => {
    if (protocolInput.trim()) {
      setFormData({
        ...formData,
        supportedProtocols: [...(formData.supportedProtocols || []), protocolInput.trim()].filter(
          (p, i, arr) => arr.indexOf(p) === i
        ),
      });
      setProtocolInput("");
    }
  };

  const removeProtocol = (protocol: string) => {
    setFormData({
      ...formData,
      supportedProtocols: (formData.supportedProtocols || []).filter((p) => p !== protocol),
    });
  };

  const addCVE = () => {
    const cvePattern = /^CVE-\d{4}-\d{4,7}$/i;
    if (cvePattern.test(cveInput.trim())) {
      setFormData({
        ...formData,
        cves: [...(formData.cves || []), cveInput.trim().toUpperCase()].filter(
          (c, i, arr) => arr.indexOf(c) === i
        ),
      });
      setCveInput("");
      setFieldErrors((prev) => ({ ...prev, cve: undefined }));
    } else if (cveInput.trim()) {
      setFieldErrors((prev) => ({ ...prev, cve: "Invalid CVE format. Expected: CVE-YYYY-NNNN" }));
    }
  };

  const removeCVE = (cve: string) => {
    setFormData({
      ...formData,
      cves: (formData.cves || []).filter((c) => c !== cve),
    });
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Request New Honeypot</CardTitle>
        <CardDescription>
          Submit a request for a new honeypot to be developed. Include technical requirements,
          protocols, ports, and any specific CVEs you&apos;d like to see implemented.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {/* Beta Trial Banner */}
        <Alert severity="info" sx={{ mb: 3 }}>
          The honeypot request feature is a free service currently under beta trial. Please submit requests to our team, and we will contact you with any follow up questions.
        </Alert>

        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Contact Information */}
          <div className="space-y-4">
            <div>
              <h3 className="text-lg font-semibold mb-2">Contact Information</h3>
              <p className="text-sm text-muted-foreground mb-4">
                Please add your contact details so someone from our STINGAR team can contact you with any questions.
              </p>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <Label htmlFor="requesterName">Your Name *</Label>
                  <Input
                    id="requesterName"
                    required
                    value={formData.requesterName || ""}
                    onChange={(e) => {
                      setFormData({ ...formData, requesterName: e.target.value });
                      if (fieldErrors.requesterName) setFieldErrors((prev) => ({ ...prev, requesterName: undefined }));
                    }}
                    placeholder="Enter your name"
                    aria-invalid={!!fieldErrors.requesterName}
                    aria-describedby={fieldErrors.requesterName ? "requesterName-error" : undefined}
                    className={fieldErrors.requesterName ? "border-red-500" : ""}
                  />
                  {fieldErrors.requesterName && (
                    <div id="requesterName-error" role="alert" aria-live="polite" className="mt-1 text-sm text-red-500 flex items-center gap-1">
                      <AlertCircle className="h-4 w-4 flex-shrink-0" aria-hidden />
                      <span>{fieldErrors.requesterName}</span>
                    </div>
                  )}
                </div>
                <div>
                  <Label htmlFor="requesterEmail">Email *</Label>
                  <Input
                    id="requesterEmail"
                    type="email"
                    required
                    autoComplete="email"
                    value={formData.requesterEmail || ""}
                    onChange={(e) => {
                      setFormData({ ...formData, requesterEmail: e.target.value });
                      if (fieldErrors.requesterEmail) setFieldErrors((prev) => ({ ...prev, requesterEmail: undefined }));
                    }}
                    placeholder="your.email@example.com"
                    aria-invalid={!!fieldErrors.requesterEmail}
                    aria-describedby={fieldErrors.requesterEmail ? "requesterEmail-error" : undefined}
                    className={fieldErrors.requesterEmail ? "border-red-500" : ""}
                  />
                  {fieldErrors.requesterEmail && (
                    <div id="requesterEmail-error" role="alert" aria-live="polite" className="mt-1 text-sm text-red-500 flex items-center gap-1">
                      <AlertCircle className="h-4 w-4 flex-shrink-0" aria-hidden />
                      <span>{fieldErrors.requesterEmail}</span>
                    </div>
                  )}
                </div>
                <div>
                  <Label htmlFor="requesterOrganization">Organization *</Label>
                  <Input
                    id="requesterOrganization"
                    required
                    value={formData.requesterOrganization || ""}
                    onChange={(e) => {
                      setFormData({ ...formData, requesterOrganization: e.target.value });
                      if (fieldErrors.requesterOrganization) setFieldErrors((prev) => ({ ...prev, requesterOrganization: undefined }));
                    }}
                    placeholder="Your organization"
                    aria-invalid={!!fieldErrors.requesterOrganization}
                    aria-describedby={fieldErrors.requesterOrganization ? "requesterOrganization-error" : undefined}
                    className={fieldErrors.requesterOrganization ? "border-red-500" : ""}
                  />
                  {fieldErrors.requesterOrganization && (
                    <div id="requesterOrganization-error" role="alert" aria-live="polite" className="mt-1 text-sm text-red-500 flex items-center gap-1">
                      <AlertCircle className="h-4 w-4 flex-shrink-0" aria-hidden />
                      <span>{fieldErrors.requesterOrganization}</span>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Basic Information */}
          <div className="space-y-4">
            <div>
              <Label htmlFor="title">Title *</Label>
              <Input
                id="title"
                value={formData.title}
                onChange={(e) => {
                  setFormData({ ...formData, title: e.target.value });
                  if (fieldErrors.title) setFieldErrors((prev) => ({ ...prev, title: undefined }));
                }}
                placeholder="e.g., Apache Struts Honeypot"
                required
                minLength={5}
                maxLength={255}
                aria-invalid={!!fieldErrors.title}
                aria-describedby={fieldErrors.title ? "title-error" : undefined}
                className={fieldErrors.title ? "border-red-500" : ""}
              />
              {fieldErrors.title && (
                <div id="title-error" role="alert" aria-live="polite" className="mt-1 text-sm text-red-500 flex items-center gap-1">
                  <AlertCircle className="h-4 w-4 flex-shrink-0" aria-hidden />
                  <span>{fieldErrors.title}</span>
                </div>
              )}
            </div>

            <div>
              <Label htmlFor="description">Description *</Label>
              <Textarea
                id="description"
                value={formData.description}
                onChange={(e) => {
                  setFormData({ ...formData, description: e.target.value });
                  if (fieldErrors.description) setFieldErrors((prev) => ({ ...prev, description: undefined }));
                }}
                placeholder="Describe the honeypot you&apos;d like to see developed..."
                required
                minLength={20}
                rows={5}
                aria-invalid={!!fieldErrors.description}
                aria-describedby={fieldErrors.description ? "description-error" : undefined}
                className={fieldErrors.description ? "border-red-500" : ""}
              />
              {fieldErrors.description && (
                <div id="description-error" role="alert" aria-live="polite" className="mt-1 text-sm text-red-500 flex items-center gap-1">
                  <AlertCircle className="h-4 w-4 flex-shrink-0" aria-hidden />
                  <span>{fieldErrors.description}</span>
                </div>
              )}
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label htmlFor="category">Category</Label>
                <Input
                  id="category"
                  value={formData.category || ""}
                  onChange={(e) => setFormData({ ...formData, category: e.target.value })}
                  placeholder="e.g., Web Server"
                />
              </div>

              <div>
                <Label htmlFor="priority">Priority</Label>
                <Select
                  value={formData.priority}
                  onValueChange={(value: RequestPriority) =>
                    setFormData({ ...formData, priority: value })
                  }
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="low">Low</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="critical">Critical</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          </div>

          {/* Technical Requirements */}
          <div className="space-y-4">
            <h3 className="text-lg font-semibold">Technical Requirements</h3>

            {/* Ports */}
            <div>
              <Label>Required Ports</Label>
              <div className="flex gap-2 mt-1">
                <Input
                  type="number"
                  min="1"
                  max="65535"
                  value={portInput}
                  onChange={(e) => setPortInput(e.target.value)}
                  placeholder="Port number (1-65535)"
                  onKeyPress={(e) => {
                    if (e.key === "Enter") {
                      e.preventDefault();
                      addPort();
                    }
                  }}
                />
                <Button type="button" onClick={addPort} variant="outlined">
                  Add Port
                </Button>
              </div>
              {formData.requiredPorts && formData.requiredPorts.length > 0 && (
                <div className="flex flex-wrap gap-2 mt-2">
                  {formData.requiredPorts.map((port) => (
                    <span
                      key={port}
                      className="px-2 py-1 bg-blue-100 text-blue-800 rounded flex items-center gap-1"
                    >
                      {port}
                      <button
                        type="button"
                        onClick={() => removePort(port)}
                        className="text-blue-600 hover:text-blue-800"
                      >
                        ×
                      </button>
                    </span>
                  ))}
                </div>
              )}
            </div>

            {/* Protocols */}
            <div>
              <Label>Supported Protocols</Label>
              <div className="flex gap-2 mt-1">
                <Input
                  value={protocolInput}
                  onChange={(e) => setProtocolInput(e.target.value)}
                  placeholder="e.g., SSH, HTTP, FTP"
                  onKeyPress={(e) => {
                    if (e.key === "Enter") {
                      e.preventDefault();
                      addProtocol();
                    }
                  }}
                />
                <Button type="button" onClick={addProtocol} variant="outlined">
                  Add Protocol
                </Button>
              </div>
              {formData.supportedProtocols && formData.supportedProtocols.length > 0 && (
                <div className="flex flex-wrap gap-2 mt-2">
                  {formData.supportedProtocols.map((protocol) => (
                    <span
                      key={protocol}
                      className="px-2 py-1 bg-green-100 text-green-800 rounded flex items-center gap-1"
                    >
                      {protocol}
                      <button
                        type="button"
                        onClick={() => removeProtocol(protocol)}
                        className="text-green-600 hover:text-green-800"
                      >
                        ×
                      </button>
                    </span>
                  ))}
                </div>
              )}
            </div>

            {/* IP Protocol Support */}
            <div>
              <Label>IP Protocol Support</Label>
              <div className="flex gap-4 mt-2">
                <label className="flex items-center gap-2">
                  <Checkbox
                    checked={formData.ipProtocolSupport?.includes("IPv4")}
                    onCheckedChange={(checked) => {
                      const current = formData.ipProtocolSupport || [];
                      if (checked) {
                        setFormData({
                          ...formData,
                          ipProtocolSupport: [...current, "IPv4"],
                        });
                      } else {
                        setFormData({
                          ...formData,
                          ipProtocolSupport: current.filter((p) => p !== "IPv4"),
                        });
                      }
                    }}
                  />
                  <span>IPv4</span>
                </label>
                <label className="flex items-center gap-2">
                  <Checkbox
                    checked={formData.ipProtocolSupport?.includes("IPv6")}
                    onCheckedChange={(checked) => {
                      const current = formData.ipProtocolSupport || [];
                      if (checked) {
                        setFormData({
                          ...formData,
                          ipProtocolSupport: [...current, "IPv6"],
                        });
                      } else {
                        setFormData({
                          ...formData,
                          ipProtocolSupport: current.filter((p) => p !== "IPv6"),
                        });
                      }
                    }}
                  />
                  <span>IPv6</span>
                </label>
              </div>
            </div>

            {/* CVEs */}
            <div>
              <Label htmlFor="cve-input">CVEs to Implement</Label>
              <div className="flex gap-2 mt-1">
                <Input
                  id="cve-input"
                  value={cveInput}
                  onChange={(e) => {
                    setCveInput(e.target.value);
                    if (fieldErrors.cve) setFieldErrors((prev) => ({ ...prev, cve: undefined }));
                  }}
                  placeholder="e.g., CVE-2021-1234"
                  aria-invalid={!!fieldErrors.cve}
                  aria-describedby={fieldErrors.cve ? "cve-error" : undefined}
                  className={fieldErrors.cve ? "border-red-500" : ""}
                  onKeyPress={(e) => {
                    if (e.key === "Enter") {
                      e.preventDefault();
                      addCVE();
                    }
                  }}
                />
                <Button type="button" onClick={addCVE} variant="outlined">
                  Add CVE
                </Button>
              </div>
              {fieldErrors.cve && (
                <div id="cve-error" role="alert" aria-live="polite" className="mt-1 text-sm text-red-500 flex items-center gap-1">
                  <AlertCircle className="h-4 w-4 flex-shrink-0" aria-hidden />
                  <span>{fieldErrors.cve}</span>
                </div>
              )}
              {formData.cves && formData.cves.length > 0 && (
                <div className="flex flex-wrap gap-2 mt-2">
                  {formData.cves.map((cve) => (
                    <span
                      key={cve}
                      className="px-2 py-1 bg-red-100 text-red-800 rounded flex items-center gap-1"
                    >
                      {cve}
                      <button
                        type="button"
                        onClick={() => removeCVE(cve)}
                        className="text-red-600 hover:text-red-800"
                      >
                        ×
                      </button>
                    </span>
                  ))}
                </div>
              )}
            </div>

            <div>
              <Label htmlFor="additionalRequirements">Additional Requirements</Label>
              <Textarea
                id="additionalRequirements"
                value={formData.additionalRequirements || ""}
                onChange={(e) =>
                  setFormData({ ...formData, additionalRequirements: e.target.value })
                }
                placeholder="Any other technical requirements or specifications..."
                rows={3}
              />
            </div>
          </div>

          {/* Optional Information */}
          <div className="space-y-4">
            <h3 className="text-lg font-semibold">Additional Information (Optional)</h3>

            <div>
              <Label htmlFor="useCases">Use Cases</Label>
              <Textarea
                id="useCases"
                value={formData.useCases || ""}
                onChange={(e) => setFormData({ ...formData, useCases: e.target.value })}
                placeholder="Describe the use cases for this honeypot..."
                rows={3}
              />
            </div>

            <div>
              <Label htmlFor="expectedBehavior">Expected Behavior</Label>
              <Textarea
                id="expectedBehavior"
                value={formData.expectedBehavior || ""}
                onChange={(e) =>
                  setFormData({ ...formData, expectedBehavior: e.target.value })
                }
                placeholder="Describe how you expect this honeypot to behave..."
                rows={3}
              />
            </div>

            <div>
              <Label htmlFor="securityConsiderations">Security Considerations</Label>
              <Textarea
                id="securityConsiderations"
                value={formData.securityConsiderations || ""}
                onChange={(e) =>
                  setFormData({ ...formData, securityConsiderations: e.target.value })
                }
                placeholder="Any security considerations or concerns..."
                rows={3}
              />
            </div>
          </div>

          {/* Submit Buttons */}
          <div className="flex justify-end gap-3">
            {onCancel && (
              <Button type="button" variant="outlined" onClick={onCancel}>
                Cancel
              </Button>
            )}
            <Button type="submit" variant="contained" disabled={isSubmitting}>
              {isSubmitting ? "Submitting..." : "Submit Request"}
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

