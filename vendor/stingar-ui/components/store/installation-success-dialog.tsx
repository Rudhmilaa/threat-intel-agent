"use client";

import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@mui/material";
import { CheckCircle, Rocket, Download } from "lucide-react";
import { useRouter } from "next/navigation";

interface InstallationSuccessDialogProps {
    open: boolean;
    onClose: () => void;
    honeypotName: string;
    onDownloadAnother?: () => void;
}

export function InstallationSuccessDialog({
    open,
    onClose,
    honeypotName,
    onDownloadAnother
}: InstallationSuccessDialogProps) {
    const router = useRouter();

    const handleGoToDeploy = () => {
        onClose();
        router.push('/deploy');
    };

    const handleDownloadAnother = () => {
        onClose();
        if (onDownloadAnother) {
            onDownloadAnother();
        } else {
            // Default behavior: scroll to top
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }
    };

    return (
        <Dialog open={open} onOpenChange={onClose}>
            <DialogContent className="sm:max-w-lg !p-8 !box-border !overflow-hidden">
                <DialogHeader className="space-y-4 pb-6 !m-0">
                    <div className="flex items-center justify-center mb-2">
                        <div className="rounded-full bg-green-100 p-4">
                            <CheckCircle className="h-10 w-10 text-green-600" />
                        </div>
                    </div>
                    <DialogTitle className="text-center text-2xl !mb-2">
                        Installation Successful!
                    </DialogTitle>
                    <DialogDescription className="text-center text-base pt-2 pb-2 !mt-0">
                        <span className="font-semibold text-foreground">{honeypotName}</span> has been installed successfully.
                        <br className="mb-2" />
                        <span className="mt-3 block">What would you like to do next?</span>
                    </DialogDescription>
                </DialogHeader>
                <DialogFooter className="!flex-col sm:!flex-row !gap-3 !pt-6 !mt-0 !mb-0 sm:!justify-start !w-full !box-border !min-w-0">
                    <Button
                        onClick={handleDownloadAnother}
                        variant="outlined"
                        color="primary"
                        startIcon={<Download className="h-4 w-4" />}
                        sx={{
                            minHeight: '44px',
                            fontSize: '0.95rem',
                            width: { xs: '100%', sm: 'auto' },
                            flex: { xs: '1 1 auto', sm: '0 0 auto' },
                            whiteSpace: 'nowrap',
                            boxSizing: 'border-box',
                            '&.MuiButton-fullWidth': {
                                width: { xs: '100%', sm: 'auto' }
                            }
                        }}
                    >
                        Download Another Honeypot
                    </Button>
                    <Button
                        onClick={handleGoToDeploy}
                        variant="contained"
                        color="primary"
                        startIcon={<Rocket className="h-4 w-4" />}
                        sx={{
                            minHeight: '44px',
                            fontSize: '0.95rem',
                            width: { xs: '100%', sm: 'auto' },
                            flex: { xs: '1 1 auto', sm: '0 0 auto' },
                            whiteSpace: 'nowrap',
                            boxSizing: 'border-box',
                            '&.MuiButton-fullWidth': {
                                width: { xs: '100%', sm: 'auto' }
                            }
                        }}
                    >
                        Go to Deploy Page
                    </Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
}

