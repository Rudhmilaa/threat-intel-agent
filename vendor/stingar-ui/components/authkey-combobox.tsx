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
import {useKeys} from "@/components/hooks/hooks";

export type AuthKeyComboboxProps = {
  className?: string;
  defaultValue?: string;
  onValueChange?: (value: string) => void;
};

export function AuthKeyCombobox({
  className,
  defaultValue = "",
  onValueChange,
}: AuthKeyComboboxProps) {
  const [open, setOpen] = React.useState(false);
  const [value, setValue] = React.useState(defaultValue);

  const {keys, isLoading, error} = useKeys();

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
          className={cn("justify-between text-wrap", className)}
        >
          {value
            ? keys?.find((authkey) => authkey.id.toString() === value)?.name
            : "Select Authentication key..."}
          <ChevronsUpDown className="w-4 h-4 ml-2 opacity-50 shrink-0" />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="max-w-lg p-0 ">
        <Command filter={filter}>
          <CommandInput placeholder="Search keys..." />
          <CommandEmpty>No results found.</CommandEmpty>
          <CommandGroup>
            {keys?.map((authkey) => (
              <CommandItem
                key={authkey.id}
                value={authkey.id.toString()}
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
                    value === authkey.id.toString()
                      ? "opacity-100"
                      : "opacity-0"
                  )}
                />
                {authkey.name}
              </CommandItem>
            ))}
          </CommandGroup>
        </Command>
      </PopoverContent>
    </Popover>
  );
}
