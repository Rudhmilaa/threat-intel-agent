"use client";

import { useState, useCallback, useEffect } from "react";
import { Button } from "@mui/material";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ArrowLeft, Plus, ThumbsUp } from "lucide-react";
import { HoneypotRequestForm } from "@/components/store/honeypot-request-form";
import { Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog";
import { HoneypotRequest } from "@/models/hp-request";
import { useUser } from "@/components/hooks/hooks";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import { useRouter } from "next/navigation";
import { LoadingState, ErrorState, EmptyState } from "@/components/store/store-states";

export default function RequestedHoneypots() {
  const [showRequestDialog, setShowRequestDialog] = useState(false);
  const [requests, setRequests] = useState<HoneypotRequest[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [userVotes, setUserVotes] = useState<Set<number>>(new Set());
  const [votingInProgress, setVotingInProgress] = useState<Set<number>>(new Set());
  const { user } = useUser();
  const router = useRouter();

  // Fetch requests function - reusable for refresh after votes
  const fetchRequests = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      // Fetch pending, in_review, and in_development requests separately and combine
      const [pendingResponse, inReviewResponse, inDevelopmentResponse] = await Promise.all([
        fetch('/api/store/requests?status=pending&perPage=20'),
        fetch('/api/store/requests?status=in_review&perPage=20'),
        fetch('/api/store/requests?status=in_development&perPage=20')
      ]);

      const allRequests: HoneypotRequest[] = [];

      if (pendingResponse.ok) {
        const pendingData = await pendingResponse.json();
        // Handle both wrapped and unwrapped responses
        if (pendingData && pendingData.data && Array.isArray(pendingData.data)) {
          allRequests.push(...pendingData.data);
        } else if (Array.isArray(pendingData)) {
          allRequests.push(...pendingData);
        }
      } else {
        const errorText = await pendingResponse.text();
        if (process.env.NODE_ENV === 'development') {
          console.error('Failed to fetch pending requests:', pendingResponse.status, errorText);
        }
      }

      if (inReviewResponse.ok) {
        const inReviewData = await inReviewResponse.json();
        // Handle both wrapped and unwrapped responses
        if (inReviewData && inReviewData.data && Array.isArray(inReviewData.data)) {
          allRequests.push(...inReviewData.data);
        } else if (Array.isArray(inReviewData)) {
          allRequests.push(...inReviewData);
        }
      } else {
        const errorText = await inReviewResponse.text();
        if (process.env.NODE_ENV === 'development') {
          console.error('Failed to fetch in-review requests:', inReviewResponse.status, errorText);
        }
      }

      if (inDevelopmentResponse.ok) {
        const inDevelopmentData = await inDevelopmentResponse.json();
        // Handle both wrapped and unwrapped responses
        if (inDevelopmentData && inDevelopmentData.data && Array.isArray(inDevelopmentData.data)) {
          allRequests.push(...inDevelopmentData.data);
        } else if (Array.isArray(inDevelopmentData)) {
          allRequests.push(...inDevelopmentData);
        }
      } else {
        const errorText = await inDevelopmentResponse.text();
        if (process.env.NODE_ENV === 'development') {
          console.error('Failed to fetch in-development requests:', inDevelopmentResponse.status, errorText);
        }
      }

      // Sort by votes descending, then by date
      allRequests.sort((a, b) => {
        if (b.votes !== a.votes) {
          return b.votes - a.votes;
        }
        return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
      });

      // Limit to top 20
      const topRequests = allRequests.slice(0, 20);
      setRequests(topRequests);

      // Fetch user's vote status for each request if user is logged in
      if (user?.username && topRequests.length > 0) {
        const votePromises = topRequests.map(async (req: HoneypotRequest) => {
          try {
            const voteResponse = await fetch(
              `/api/store/requests/${req.requestId}/vote-status?userIdentifier=${encodeURIComponent(user.username)}`
            );
            if (voteResponse.ok) {
              const voteData = await voteResponse.json();
              // Handle both wrapped and unwrapped responses
              const hasVoted = voteData.has_voted || (voteData.data && voteData.data.has_voted);
              return hasVoted ? req.id : null;
            }
          } catch (error) {
            // Don't log errors for vote status - it's not critical
          }
          return null;
        });
        const votedIds = (await Promise.all(votePromises)).filter(id => id !== null);
        setUserVotes(new Set(votedIds));
      }
    } catch (error) {
      if (process.env.NODE_ENV === 'development') {
        console.error('Error fetching requests:', error);
      }
      setError('Failed to load requested honeypots');
    } finally {
      setIsLoading(false);
    }
  }, [user?.username]);

  // Fetch requests on mount
  useEffect(() => {
    fetchRequests();
  }, [fetchRequests]);

  // Voting function
  const handleVote = async (requestId: string, requestDbId: number) => {
    if (!user?.username) {
      toast.error("Please log in to vote");
      return;
    }

    // Prevent duplicate votes - check if user already voted or vote is in progress
    if (userVotes.has(requestDbId) || votingInProgress.has(requestDbId)) {
      return; // Already voted or vote in progress, silently return
    }

    // Mark vote as in progress
    setVotingInProgress(prev => new Set([...prev, requestDbId]));

    try {
      const response = await fetch(`/api/store/requests/${requestId}/vote`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userIdentifier: user.username })
      });

      if (response.ok) {
        const result = await response.json();
        // Handle both wrapped and unwrapped responses
        const votes = result.votes || (result.data && result.data.votes) || result;
        setUserVotes(new Set([...userVotes, requestDbId]));
        // Refresh requests from server to get accurate vote counts (including votes from other instances)
        await fetchRequests();
        toast.success("Vote added!");
      } else if (response.status === 400) {
        // User already voted - this is expected behavior, not an error
        // Silently handle - don't show error toast or log to console
        // Mark as voted in UI to prevent future attempts
        setUserVotes(new Set([...userVotes, requestDbId]));
        // Don't show toast for expected 400 errors (already voted)
        // Don't log 400 errors - they're expected when user already voted
      } else {
        const errorText = await response.text();
        let errorData;
        try {
          errorData = JSON.parse(errorText);
        } catch {
          errorData = { error: errorText || 'Failed to vote' };
        }
        // Only log unexpected errors in development
        if (process.env.NODE_ENV === 'development') {
          console.error('Vote error:', errorData);
        }
        toast.error(errorData.error || errorData.detail || 'Failed to vote');
      }
    } catch (error: any) {
      // Only log unexpected errors in development
      if (process.env.NODE_ENV === 'development') {
        console.error('Error voting:', error);
      }
      toast.error(error.message || 'Failed to vote');
    } finally {
      // Remove from voting in progress
      setVotingInProgress(prev => {
        const next = new Set(prev);
        next.delete(requestDbId);
        return next;
      });
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <Button
            onClick={() => router.push('/hp-store')}
            variant="outlined"
            size="small"
            startIcon={<ArrowLeft className="h-4 w-4" />}
          >
            Back to Store
          </Button>
          <div>
            <h1 className="text-xl font-bold">Requested Honeypots</h1>
            <p className="text-muted-foreground">
              These honeypots are under development and not yet available for download. Upvote requests you&apos;d like to see prioritized.
            </p>
          </div>
        </div>
        <Button
          onClick={() => setShowRequestDialog(true)}
          variant="contained"
          color="primary"
          size="small"
          startIcon={<Plus className="h-4 w-4" />}
        >
          Request New Honeypot
        </Button>
      </div>

      {/* Content */}
      <div className="space-y-6">
        {/* Loading State */}
        {isLoading && <LoadingState message="Loading requested honeypots..." />}

        {/* Error State */}
        {error && (
          <ErrorState
            error={new Error(error)}
            onRetry={fetchRequests}
            title="Failed to load requested honeypots"
          />
        )}

        {/* Empty State */}
        {!isLoading && !error && requests.length === 0 && (
          <EmptyState
            title="No honeypot requests yet"
            description="Be the first to request a new honeypot configuration. Click the button above to submit your request."
          />
        )}

        {/* Requests Grid */}
        {!isLoading && !error && requests.length > 0 && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {requests.map((request) => (
              <Card key={`request-${request.id}`} className="border-2 border-dashed border-blue-200 bg-blue-50/50">
                <CardHeader>
                  <div className="flex items-start justify-between">
                    <CardTitle className="text-lg">{request.title}</CardTitle>
                    <Badge variant="outline" className="bg-blue-100 text-blue-800">
                      {request.status}
                    </Badge>
                  </div>
                  <CardDescription className="line-clamp-3">
                    {request.description}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 mb-4">
                    {request.requiredPorts && request.requiredPorts.length > 0 && (
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-medium text-muted-foreground">Ports:</span>
                        <div className="flex flex-wrap gap-1">
                          {request.requiredPorts.map((port) => (
                            <Badge key={port} variant="secondary" className="text-xs">
                              {port}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    )}
                    {request.supportedProtocols && request.supportedProtocols.length > 0 && (
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-medium text-muted-foreground">Protocols:</span>
                        <div className="flex flex-wrap gap-1">
                          {request.supportedProtocols.map((protocol) => (
                            <Badge key={protocol} variant="secondary" className="text-xs">
                              {protocol}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    )}
                    {request.cves && request.cves.length > 0 && (
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-medium text-muted-foreground">CVEs:</span>
                        <div className="flex flex-wrap gap-1">
                          {request.cves.map((cve) => (
                            <Badge key={cve} variant="destructive" className="text-xs">
                              {cve}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                  <div className="flex items-center justify-between pt-4 border-t">
                    <Button
                      variant={userVotes.has(request.id) ? "contained" : "outlined"}
                      size="small"
                      startIcon={<ThumbsUp className="h-4 w-4" />}
                      onClick={() => handleVote(request.requestId, request.id)}
                      disabled={userVotes.has(request.id) || !user?.username || votingInProgress.has(request.id)}
                      color={userVotes.has(request.id) ? "success" : "primary"}
                    >
                      {request.votes} {request.votes === 1 ? 'vote' : 'votes'}
                    </Button>
                    <span className="text-xs text-muted-foreground">
                      {new Date(request.createdAt).toLocaleDateString()}
                    </span>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>

      {/* Request Dialog */}
      <Dialog open={showRequestDialog} onOpenChange={setShowRequestDialog}>
        <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
          <DialogTitle>Request New Honeypot</DialogTitle>
          <HoneypotRequestForm
            onSuccess={() => {
              setShowRequestDialog(false);
              fetchRequests();
            }}
            onCancel={() => setShowRequestDialog(false)}
          />
        </DialogContent>
      </Dialog>
    </div>
  );
}

