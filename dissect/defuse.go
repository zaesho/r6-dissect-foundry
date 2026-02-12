package dissect

import (
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
)

// getTeamByRole returns the team index with the specified role (Attack or Defense)
func (r *Reader) getTeamByRole(role TeamRole) int {
	for i, team := range r.Header.Teams {
		if team.Role == role {
			return i
		}
	}
	return -1
}

// getAlivePlayersByTeam returns usernames of players who haven't died yet on a team
func (r *Reader) getAlivePlayersByTeam(teamIndex int) []string {
	var alive []string
	for _, p := range r.Header.Players {
		if p.TeamIndex == teamIndex {
			// Check if player has died
			died := false
			for _, fb := range r.MatchFeedback {
				if fb.Type == Kill && fb.Target == p.Username {
					died = true
					break
				}
				if fb.Type == Death && fb.Username == p.Username {
					died = true
					break
				}
			}
			if !died && p.Username != "" {
				alive = append(alive, p.Username)
			}
		}
	}
	return alive
}

// findAlivePlayersOfRole returns indices of players who are alive at the current timestamp
// and belong to a team with the specified role.
// Note: R6 uses countdown time, so lower time values mean later in the round.
func (r *Reader) findAlivePlayersOfRole(role TeamRole) []int {
	// Build a set of players who have been killed before the current time
	// In countdown time: an event at timeInSeconds X happened before current time Y if X > Y
	// (e.g., kill at 1:00 (60s) happened before current time 0:40 (40s))
	deadPlayers := make(map[string]bool)
	for _, update := range r.MatchFeedback {
		// Only consider Kill/Death events that happened before current time
		// Higher timeInSeconds = earlier in the round (countdown)
		if update.TimeInSeconds < r.time {
			// This event happened AFTER current time in the round
			continue
		}
		if update.Type == Kill && update.Target != "" {
			deadPlayers[update.Target] = true
		}
		if update.Type == Death {
			deadPlayers[update.Username] = true
		}
	}

	// Find alive players of the specified role
	var alivePlayers []int
	for idx, p := range r.Header.Players {
		if r.Header.Teams[p.TeamIndex].Role != role {
			continue
		}
		if !deadPlayers[p.Username] {
			alivePlayers = append(alivePlayers, idx)
		}
	}

	return alivePlayers
}

func readDefuserTimer(r *Reader) error {
	timer, err := r.String()
	if err != nil {
		return err
	}
	prevTimer := r.lastDefuserTimer
	timerValue := -1.0
	if len(timer) > 0 {
		if v, parseErr := strconv.ParseFloat(timer, 64); parseErr == nil {
			timerValue = v
		}
	}

	var i int = -1

	if r.Header.CodeVersion >= Y10S4 {
		// Y10S4 changed packet structure - player DissectID is no longer included
		// Try to infer from team roles: attackers plant, defenders disable
		var targetRole TeamRole
		if r.planted {
			targetRole = Defense // Defender is disabling
		} else {
			targetRole = Attack // Attacker is planting
		}

		teamIndex := r.getTeamByRole(targetRole)
		if teamIndex >= 0 {
			alive := r.getAlivePlayersByTeam(teamIndex)
			if len(alive) == 1 {
				// Only one player alive on that team - must be them
				for idx, p := range r.Header.Players {
					if p.Username == alive[0] {
						i = idx
						break
					}
				}
			}
		}
	} else {
		if err = r.Skip(34); err != nil {
			return err
		}
		id, err := r.Bytes(4)
		if err != nil {
			return err
		}
		i = r.PlayerIndexByID(id)
	}

	a := DefuserPlantStart
	recordStartEvent := true
	if r.planted {
		if timerValue >= 0 && prevTimer >= 0 && timerValue > prevTimer {
			a = DefuserDisableStart
			r.defuserDisabling = true
		} else {
			recordStartEvent = false
		}
	} else {
		r.defuserDisabling = false
	}

	if recordStartEvent && i > -1 && r.lastDefuserPlayerIndex != i {
		u := MatchUpdate{
			Type:          a,
			Username:      r.Header.Players[i].Username,
			Time:          r.timeRaw,
			TimeInSeconds: r.time,
		}
		r.MatchFeedback = append(r.MatchFeedback, u)
		log.Debug().Interface("match_update", u).Send()
		r.lastDefuserPlayerIndex = i
	}
	// TODO: 0.00 can be present even if defuser was not disabled.
	if !strings.HasPrefix(timer, "0.00") {
		r.lastDefuserTimer = timerValue
		return nil
	}
	eventType := DefuserDisableComplete
	if !r.planted {
		eventType = DefuserPlantComplete
		r.planted = true
		r.defuserDisabling = false
	} else if r.defuserDisabling {
		eventType = DefuserDisableComplete
		r.defuserDisabling = false
		r.planted = false
	} else {
		r.lastDefuserTimer = timerValue
		return nil
	}
	// Use current player index if available, otherwise fall back to lastDefuserPlayerIndex
	playerIdx := r.lastDefuserPlayerIndex
	if i > -1 {
		playerIdx = i
	}
	// If we still don't have a valid player, try to infer from team roles
	// For plant complete: find an attacker who is alive at this timestamp
	// For defuse complete: find a defender who is alive at this timestamp
	if playerIdx < 0 || playerIdx >= len(r.Header.Players) {
		targetRole := Attack
		if eventType == DefuserDisableComplete {
			targetRole = Defense
		}
		// Find players of the correct team who are still alive
		alivePlayers := r.findAlivePlayersOfRole(targetRole)
		if len(alivePlayers) == 1 {
			// Only one player alive of this role - must be them
			playerIdx = alivePlayers[0]
			log.Debug().Int("playerIdx", playerIdx).Str("username", r.Header.Players[playerIdx].Username).Msg("defuser action: single alive player identified")
		} else if len(alivePlayers) > 1 {
			// Multiple players alive - check if lastDefuserPlayerIndex is among them
			lastIdxValid := false
			for _, idx := range alivePlayers {
				if idx == r.lastDefuserPlayerIndex {
					lastIdxValid = true
					break
				}
			}
			if lastIdxValid && r.lastDefuserPlayerIndex >= 0 {
				playerIdx = r.lastDefuserPlayerIndex
			} else {
				// Fall back to first alive player of the role
				playerIdx = alivePlayers[0]
			}
			log.Debug().Int("playerIdx", playerIdx).Int("aliveCount", len(alivePlayers)).Msg("defuser action: multiple alive players, using best guess")
		} else {
			// No alive players found - fall back to first player of the role (legacy behavior)
			for idx, p := range r.Header.Players {
				if r.Header.Teams[p.TeamIndex].Role == targetRole {
					playerIdx = idx
					break
				}
			}
			log.Debug().Int("playerIdx", playerIdx).Msg("defuser action: no alive players found, using fallback")
		}
	}

	username := ""
	if playerIdx >= 0 && playerIdx < len(r.Header.Players) {
		username = r.Header.Players[playerIdx].Username
	}

	u := MatchUpdate{
		Type:          eventType,
		Username:      username,
		Time:          r.timeRaw,
		TimeInSeconds: r.time,
	}
	r.MatchFeedback = append(r.MatchFeedback, u)
	log.Debug().Interface("match_update", u).Send()

	r.lastDefuserTimer = timerValue
	return nil
}
