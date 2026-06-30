// import React from "react";
// import {useBlocklist} from "@/components/hooks/hooks";
// import DataTable from "./table";
// // import {Button, Input, SortDescriptor} from "@nextui-org/react";
// import {SearchIcon, Trash} from "lucide-react";
// import {sortItems} from "@/lib/utils";
// import {deleteBlockedIP} from "@/lib/actions";
// import AddBlockedIPDialogButton from "../dialogs/add-blocked-ip";
// import {toast} from "sonner";
// import DeleteBlockedIpsDialog from "../dialogs/delete-blocked-ips";

// const columns = [
//   {key: "created", label: "Created", allowsSorting: true, sortType: "date"},
//   {
//     key: "address",
//     label: "IP Address",
//     allowsSorting: true,
//     sortType: "string",
//   },
//   {key: "actions", label: "Remove"},
// ];

// function TopContent({
//   filterValue,
//   onFilterValueChange,
//   onClear,
// }: {
//   filterValue: string;
//   onFilterValueChange: (value: string) => void;
//   onClear: () => void;
// }) {
//   return (
//     <div className="flex flex-col gap-4">
//       <p className="text-md ">Blocklist</p>
//       <div className="flex items-center justify-between gap-4">
//         <Input
//           isClearable
//           className="w-full max-w-[65%]"
//           placeholder="Search by IP Address..."
//           startContent={<SearchIcon />}
//           value={filterValue}
//           onClear={() => onClear()}
//           onValueChange={onFilterValueChange}
//         />
//         <AddBlockedIPDialogButton />
//       </div>
//     </div>
//   );
// }

// export default function BlocklistTable() {
//   return <div></div>;
//   const {blocklist, isLoading, error, mutate} = useBlocklist();
//   const [deleteOpen, setDeleteOpen] = React.useState(false);
//   const [currentPage, setCurrentPage] = React.useState(1);
//   const renderCell = React.useCallback(
//     (blockedIP: any, columnKey: React.Key) => {
//       const cellValue = blockedIP[columnKey.toString()];

//       switch (columnKey) {
//         case "created":
//           return blockedIP.created.toLocaleDateString();
//         case "actions": {
//           return (
//             <div>
//               <Button
//                 isIconOnly
//                 size="sm"
//                 variant="light"
//                 onClick={() => {
//                   deleteBlockedIP(blockedIP.id)
//                     .then(() => {
//                       toast.success("'" + blockedIP.address + "' deleted.");
//                       mutate();
//                     })
//                     .catch((error) => {
//                       toast.error(`Error deleting ${blockedIP.address}.`);
//                     });
//                   mutate();
//                 }}
//               >
//                 <Trash size={20} />
//               </Button>
//             </div>
//           );
//         }

//         default:
//           return cellValue;
//       }
//     },
//     [mutate]
//   );
//   const [filterValue, setFilterValue] = React.useState<string>("");
//   const [sortDescriptor, setSortDescriptor] = React.useState<SortDescriptor>({
//     column: "created",
//     direction: "descending",
//   });
//   const filteredItems = React.useMemo(() => {
//     let filteredlist = [...(blocklist ?? [])];

//     if (Boolean(filterValue)) {
//       filteredlist = filteredlist.filter((ip) =>
//         ip.address.toLowerCase().includes(filterValue.toLowerCase())
//       );
//     }
//     return filteredlist;
//   }, [blocklist, filterValue]);

//   const sortedItems = React.useMemo(() => {
//     const sortType = columns.find((col) => col.key === sortDescriptor.column)
//       ?.sortType as "string" | "number" | "date" | undefined;
//     return sortItems(filteredItems, sortDescriptor, sortType ?? "string");
//   }, [filteredItems, sortDescriptor]);

//   const onSortChange = React.useCallback((descriptor: SortDescriptor) => {
//     setSortDescriptor(descriptor);
//     setCurrentPage(1);
//   }, []);

//   const onFilterValueChange = React.useCallback((value: string) => {
//     if (value) {
//       setFilterValue(value);
//       setCurrentPage(1);
//     } else {
//       setFilterValue("");
//     }
//   }, []);
//   const onClear = React.useCallback(() => {
//     setFilterValue("");
//     setCurrentPage(1);
//   }, []);
//   // return (
//   //   <div>
//   //     <DataTable
//   //       data={sortedItems}
//   //       columns={columns}
//   //       isLoading={isLoading}
//   //       error={error}
//   //       currentPage={currentPage}
//   //       onPageChange={(page) => setCurrentPage(page)}
//   //       renderCell={renderCell}
//   //       topContent={
//   //         <TopContent
//   //           filterValue={filterValue}
//   //           onFilterValueChange={onFilterValueChange}
//   //           onClear={onClear}
//   //         />
//   //       }
//   //       sortDescriptor={sortDescriptor}
//   //       onSortDescriptorChange={onSortChange}
//   //     />
//   //     <div className="pb-4 pl-2">
//   //       <Button color="danger" size="sm" onClick={() => setDeleteOpen(true)}>
//   //         Clear Blocklist
//   //       </Button>
//   //       <DeleteBlockedIpsDialog open={deleteOpen} setOpen={setDeleteOpen} />
//   //     </div>
//   //   </div>
//   // );
// }
