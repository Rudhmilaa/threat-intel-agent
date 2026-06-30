import { useState, useEffect } from 'react';
import { Button } from "@mui/material";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { Search, Filter, X, Star } from "lucide-react";
import { useCategories, useTags } from "@/lib/hooks/use-store";
import { StoreFilters } from "@/models/store";
import type { Category, Tag } from "@/models/store";

interface SearchFiltersProps {
  filters: StoreFilters;
  onFiltersChange: (filters: StoreFilters) => void;
  onClearAll: () => void;
}

export function SearchFilters({
  filters,
  onFiltersChange,
  onClearAll,
}: SearchFiltersProps) {
  const [isFilterOpen, setIsFilterOpen] = useState(false);
  const { categories, isLoading: categoriesLoading } = useCategories();
  const { tags, isLoading: tagsLoading } = useTags();

  const hasActiveFilters = Object.values(filters).some(value => value !== undefined && value !== '');

  const updateFilter = (key: keyof StoreFilters, value: string | number | undefined) => {
    onFiltersChange({
      ...filters,
      [key]: value,
    });
  };

  const clearFilter = (key: keyof StoreFilters) => {
    const newFilters = { ...filters };
    delete newFilters[key];
    onFiltersChange(newFilters);
  };

  const getActiveFiltersCount = () => {
    return Object.values(filters).filter(value => value !== undefined && value !== '').length;
  };

  return (
    <div className="space-y-4">
      {/* Filter Bar */}
      <div className="flex items-center space-x-4">

        {/* Filter Button */}
        <Popover open={isFilterOpen} onOpenChange={setIsFilterOpen}>
          <PopoverTrigger asChild>
            <Button
              variant="outlined"
              size="small"
              startIcon={<Filter className="h-4 w-4" />}
              className="relative"
            >
              Filters
              {getActiveFiltersCount() > 0 && (
                <Badge variant="secondary" className="ml-2 h-5 w-5 p-0 text-xs">
                  {getActiveFiltersCount()}
                </Badge>
              )}
            </Button>
          </PopoverTrigger>
          <PopoverContent className="w-80" align="end">
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h4 className="font-medium">Filters</h4>
                {hasActiveFilters && (
                  <Button
                    variant="text"
                    size="small"
                    onClick={onClearAll}
                    className="h-6 px-2 text-xs"
                  >
                    Clear all
                  </Button>
                )}
              </div>

              {/* Category Filter */}
              <div className="space-y-2">
                <label className="text-sm font-medium">Category</label>
                <Select
                  value={filters.category || 'all'}
                  onValueChange={(value) => updateFilter('category', value === 'all' ? undefined : value)}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="All categories" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All categories</SelectItem>
                    {categories.map((category: Category) => (
                      <SelectItem key={category.id} value={category.name}>
                        {category.name} ({category.honeypotCount})
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              {/* Honeypot Type Filter */}
              <div className="space-y-2">
                <label className="text-sm font-medium">Honeypot Type</label>
                <Select
                  value={filters.hpType || 'all'}
                  onValueChange={(value) => updateFilter('hpType', value === 'all' ? undefined : value)}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="All types" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All types</SelectItem>
                    <SelectItem value="SSH">SSH</SelectItem>
                    <SelectItem value="HTTP">HTTP</SelectItem>
                    <SelectItem value="RDP">RDP</SelectItem>
                    <SelectItem value="FTP">FTP</SelectItem>
                    <SelectItem value="SMTP">SMTP</SelectItem>
                    <SelectItem value="Multi-Protocol">Multi-Protocol</SelectItem>
                    <SelectItem value="ICS">ICS/SCADA</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {/* Status Filter */}
              <div className="space-y-2">
                <label className="text-sm font-medium">Status</label>
                <Select
                  value={filters.status || 'all'}
                  onValueChange={(value) => updateFilter('status', value === 'all' ? undefined : value)}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="All statuses" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All statuses</SelectItem>
                    <SelectItem value="active">Active</SelectItem>
                    <SelectItem value="beta">Beta</SelectItem>
                    <SelectItem value="deprecated">Deprecated</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {/* Rating Filter */}
              <div className="space-y-2">
                <label className="text-sm font-medium">Minimum Rating</label>
                <Select
                  value={filters.minRating?.toString() || 'all'}
                  onValueChange={(value) => updateFilter('minRating', value === 'all' ? undefined : parseFloat(value))}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Any rating" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">Any rating</SelectItem>
                    <SelectItem value="4.5">4.5+ stars</SelectItem>
                    <SelectItem value="4.0">4.0+ stars</SelectItem>
                    <SelectItem value="3.5">3.5+ stars</SelectItem>
                    <SelectItem value="3.0">3.0+ stars</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {/* Tags Filter */}
              <div className="space-y-2">
                <label className="text-sm font-medium">Tags</label>
                <div className="max-h-32 overflow-y-auto space-y-1">
                  {tags.slice(0, 10).map((tag: Tag) => (
                    <div key={tag.id} className="flex items-center space-x-2">
                      <input
                        type="checkbox"
                        id={`tag-${tag.id}`}
                        checked={filters.tags?.includes(tag.name) || false}
                        onChange={(e) => {
                          const currentTags = filters.tags ? filters.tags.split(',') : [];
                          if (e.target.checked) {
                            updateFilter('tags', [...currentTags, tag.name].join(','));
                          } else {
                            updateFilter('tags', currentTags.filter(t => t !== tag.name).join(','));
                          }
                        }}
                        className="rounded"
                      />
                      <label htmlFor={`tag-${tag.id}`} className="text-sm">
                        {tag.name} ({tag.honeypotCount})
                      </label>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </PopoverContent>
        </Popover>

        {/* Clear All Button */}
        {hasActiveFilters && (
          <Button
            variant="text"
            size="small"
            onClick={onClearAll}
            startIcon={<X className="h-4 w-4" />}
            className="text-muted-foreground hover:text-foreground"
          >
            Clear
          </Button>
        )}
      </div>

      {/* Active Filters Display */}
      {hasActiveFilters && (
        <div className="flex flex-wrap gap-2">
          {filters.category && (
            <Badge variant="secondary" className="flex items-center space-x-1">
              <span>Category: {filters.category}</span>
              <Button
                variant="text"
                size="small"
                onClick={() => clearFilter('category')}
                className="h-4 w-4 p-0 hover:bg-transparent min-w-0"
              >
                <X className="h-3 w-3" />
              </Button>
            </Badge>
          )}
          {filters.hpType && (
            <Badge variant="secondary" className="flex items-center space-x-1">
              <span>Type: {filters.hpType}</span>
              <Button
                variant="text"
                size="small"
                onClick={() => clearFilter('hpType')}
                className="h-4 w-4 p-0 hover:bg-transparent min-w-0"
              >
                <X className="h-3 w-3" />
              </Button>
            </Badge>
          )}
          {filters.status && (
            <Badge variant="secondary" className="flex items-center space-x-1">
              <span>Status: {filters.status}</span>
              <Button
                variant="text"
                size="small"
                onClick={() => clearFilter('status')}
                className="h-4 w-4 p-0 hover:bg-transparent min-w-0"
              >
                <X className="h-3 w-3" />
              </Button>
            </Badge>
          )}
          {filters.minRating && (
            <Badge variant="secondary" className="flex items-center space-x-1">
              <Star className="h-3 w-3" />
              <span>{filters.minRating}+ stars</span>
              <Button
                variant="text"
                size="small"
                onClick={() => clearFilter('minRating')}
                className="h-4 w-4 p-0 hover:bg-transparent min-w-0"
              >
                <X className="h-3 w-3" />
              </Button>
            </Badge>
          )}
          {filters.tags && (
            <Badge variant="secondary" className="flex items-center space-x-1">
              <span>Tags: {filters.tags}</span>
              <Button
                variant="text"
                size="small"
                onClick={() => clearFilter('tags')}
                className="h-4 w-4 p-0 hover:bg-transparent min-w-0"
              >
                <X className="h-3 w-3" />
              </Button>
            </Badge>
          )}
        </div>
      )}
    </div>
  );
}
