// AKA design system — shared component primitives.
// Styling tokens live in ./styles/theme.css (exported as "@aka/ui-kit/theme.css").
export { Badge, type BadgeProps, type Severity, SeverityBadge } from './badge.tsx';
export { Button, type ButtonProps } from './button.tsx';
export {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardHeading,
  CardIcon,
  CardTitle,
} from './card.tsx';
export {
  Dialog,
  DialogClose,
  DialogContent,
  type DialogContentProps,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from './dialog.tsx';
export {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from './dropdown-menu.tsx';
export { cn } from './lib/cn.ts';
export { Meter, type MeterProps } from './meter.tsx';
export {
  Popover,
  PopoverAnchor,
  PopoverClose,
  PopoverContent,
  type PopoverContentProps,
  PopoverTrigger,
} from './popover.tsx';
export {
  SegmentedControl,
  SegmentedControlItem,
  type SegmentedControlItemProps,
  type SegmentedControlProps,
} from './segmented-control.tsx';
export {
  Sheet,
  SheetClose,
  SheetContent,
  type SheetContentProps,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from './sheet.tsx';
export { Skeleton } from './skeleton.tsx';
export { Switch, type SwitchProps } from './switch.tsx';
export { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './table.tsx';
export { Tag, type TagProps } from './tag.tsx';
