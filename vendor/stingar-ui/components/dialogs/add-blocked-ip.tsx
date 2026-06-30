// import {useState} from "react";
// import {Button} from "@mui/material";
// import {
//   Dialog,
//   DialogContent,
//   DialogDescription,
//   DialogHeader,
//   DialogTitle,
// } from "@/components/ui/dialog";
// import {Input} from "../ui/input";
// import {cn} from "@/lib/utils";
// import {toast} from "sonner";
// import {useBlocklist} from "@/components/hooks/hooks";
// import {createBlockedIP} from "@/lib/actions";
// import {PlusIcon} from "lucide-react";

// function AddBlockedIPDialogButton() {
//   const {mutate} = useBlocklist();

//   const [open, setOpen] = useState(false);
//   const handleDialogOpenChange = (isOpen: boolean) => {
//     if (!isOpen) {
//       // Dialog is closing, do anything here.
//       setAddress("");
//       setFileIps([]);
//     }
//     setOpen(isOpen);
//   };

//   const [fileIps, setFileIps] = useState<string[]>([]);

//   const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
//     const file = event.target.files ? event.target.files[0] : null;
//     const reader = new FileReader();

//     reader.onload = (event) => {
//       const content = event.target?.result;
//       if (typeof content !== "string") {
//         return;
//       }

//       // Parse list of IPs
//       const ips = content
//         .split("\n")
//         .map((ip) => ip.trim())
//         .filter((ip) => ip.length > 0);

//       setFileIps(ips);
//     };
//     if (file) {
//       reader.readAsText(file);
//     }
//   };

//   const [address, setAddress] = useState("");
//   const handleAddBlockedIP = () => {
//     if (address.trim().length > 0) {
//       createBlockedIP(address)
//         .then((count) => {
//           mutate();
//           if (count === 0) {
//             toast.error("Address already exists.");
//             return;
//           }
//           toast.success("Successfully added address: " + address);
//         })
//         .catch((err) => {
//           toast.error(err.message);
//         });
//     }
//     if (fileIps.length > 0) {
//       // POST IPs
//       createBlockedIP(fileIps)
//         .then((count) => {
//           if (count === 0) {
//             toast.error("No new addresses added.");
//             return;
//           }
//           toast.success(`Successfully added ${count} new address(es).`);
//           mutate();
//         })
//         .catch((err) => {
//           toast.error("Load aborted. " + err.message);
//         });
//     }
//     handleDialogOpenChange(false);
//   };

//   return (
//     <>
//       <Button onClick={() => setOpen(true)}>Add Entry</Button>
//       <Dialog open={open} onOpenChange={handleDialogOpenChange}>
//         <DialogContent>
//           <DialogHeader>
//             <DialogTitle>Add Blocked IP</DialogTitle>
//             <DialogDescription>
//               Please enter the IP address in CIDR Notation to block (e.g.
//               10.10.10.10 or 10.10.10.0/24) or upload a file of new line
//               separated IPs.
//             </DialogDescription>
//           </DialogHeader>
//           <div>
//             <Input
//               className={cn("w-full rounded-md shadow-sm sm:text-sm")}
//               placeholder="Enter address"
//               value={address}
//               onChange={(e) => setAddress(e.target.value)}
//             />
//           </div>
//           <div className="flex justify-between">
//             <Input type="file" className="w-1/2" onChange={handleFileUpload} />
//             <Button
//               color="success"
//               variant="shadow"
//               isDisabled={address.trim().length === 0 && fileIps.length === 0}
//               onClick={() => {
//                 handleAddBlockedIP();
//               }}
//             >
//               Add Address
//             </Button>
//           </div>
//           {fileIps.length > 0 && (
//             <div className="pl-2">
//               <p className="text-sm text-gray-500">
//                 Loaded {fileIps.length} potential addresses.
//               </p>
//             </div>
//           )}
//         </DialogContent>
//       </Dialog>
//     </>
//   );
// }

// export default AddBlockedIPDialogButton;
