"use client";

import React from "react";
import {Check, ChevronsUpDown} from "lucide-react";

import {cn} from "@/lib/utils";
import {Button} from "@/components/ui/button";
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
} from "@/components/ui/command";
import {Popover, PopoverContent, PopoverTrigger} from "@/components/ui/popover";
import {useHosts, useKeys} from "@/components/hooks/hooks";

export type HostComboboxProps = {
  initialHost?: string;
  className?: string;
  onValueChange?: (value: string) => void;
};

export function HostCombobox({
  className,
  initialHost,
  onValueChange,
}: HostComboboxProps) {
  const [open, setOpen] = React.useState(false);
  const [value, setValue] = React.useState(initialHost || "");

  const {hosts} = useHosts();
  const {keys} = useKeys();

  const filter = (value: string, search: string) => {
    const val = keys?.find((val) => val.id.toString() === value)?.name;
    if (val) {
      return val.toLowerCase().includes(search.toLowerCase()) ? 1 : 0;
    }
    return 0;
  };
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="outline"
          role="combobox"
          aria-expanded={open}
          className={cn("justify-between", className)}
        >
          {value
            ? hosts?.find((host) => host.address === value)?.address
            : "Select Honeypot Host..."}
          <ChevronsUpDown className="w-4 h-4 ml-2 opacity-50 shrink-0" />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="p-0">
        <Command>
          <CommandInput placeholder="Search hosts..." />
          <CommandEmpty>No hosts found.</CommandEmpty>
          <CommandGroup>
            {hosts?.map((host) => (
              <CommandItem
                key={host.id}
                value={host.address}
                onSelect={(currentValue) => {
                  const v = currentValue === value ? "" : currentValue;
                  setValue(v);
                  onValueChange?.(v);
                  setOpen(false);
                }}
              >
                <Check
                  className={cn(
                    "mr-2 h-4 w-4",
                    value === host.address ? "opacity-100" : "opacity-0"
                  )}
                />
                {host.address}
              </CommandItem>
            ))}
          </CommandGroup>
        </Command>
      </PopoverContent>
    </Popover>
  );
}
