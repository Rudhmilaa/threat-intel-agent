import React from "react";
import {Label} from "@/components/ui/label";
import {Input} from "@/components/ui/input";
import {Check} from "lucide-react";
import {
  AccordionItem,
  AccordionTrigger,
  AccordionContent,
} from "@/components/ui/accordion";
import {ServiceConfig} from "@/models/honeypots";

type ServiceConfigItemProps = {
  serviceName: string;
  config: ServiceConfig;
  onChange: (config: ServiceConfig) => void;
};

export function ServiceConfigItem({
  serviceName,
  config,
  onChange,
}: ServiceConfigItemProps) {
  return (
    <AccordionItem value={serviceName} className="p-2 m-2 rounded-md shadow">
      <AccordionTrigger>
        <div className="flex items-center">
          <Check
            visibility={config.enabled ? "visible" : "hidden"}
            rotate={config.enabled ? 180 : 0}
          />
          <Label className="ml-4">Enable {serviceName.toUpperCase()}</Label>
        </div>
      </AccordionTrigger>
      <AccordionContent>
        <div className="flex items-center gap-4 p-2">
          <Label>Port</Label>
          <Input
            value={config.port}
            onChange={(e) => {
              const {value} = e.target;
              if (value === "" || /^[0-9]+$/.test(value)) {
                onChange({...config, port: value});
              }
            }}
            className="w-full"
            placeholder={`Enter ${serviceName.toUpperCase()} port`}
          />
        </div>
      </AccordionContent>
    </AccordionItem>
  );
}
