package admin

import (
	"context"
	"strings"

	"github.com/sapiderman/tenkei-register/internal/types"
	"github.com/uptrace/bun"
)

const (
	defaultPageSize = 25
	maxPageSize     = 100
)

// dbListUsers returns one page of member summaries plus the total matching
// row count. Filtering (viewer scope, pending, free-text search), counting,
// and pagination all run in SQL — no in-memory filtering of a full fetch.
//
// Viewer scope: an admin (level < superuser) sees only new/user rows; a
// superuser sees all rows. Multiple Where calls are AND-ed by bun.
func (a *administrator) dbListUsers(ctx context.Context, viewerLevel int, search string, pendingOnly bool, page, size int) ([]MemberSummary, int64, error) {
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = defaultPageSize
	}
	if size > maxPageSize {
		size = maxPageSize
	}
	offset := (page - 1) * size
	search = strings.TrimSpace(search)
	scoped := viewerLevel < types.RoleLevel(types.RoleSuperuser)

	// applyConds adds the shared predicates to a select query.
	applyConds := func(sel *bun.SelectQuery) *bun.SelectQuery {
		if scoped {
			sel = sel.Where("role IN ('new', 'user')")
		}
		if pendingOnly {
			sel = sel.Where("role = 'new'")
		}
		if search != "" {
			sel = sel.Where("(name ILIKE ? OR email ILIKE ?)", "%"+search+"%", "%"+search+"%")
		}
		return sel
	}

	total, err := applyConds(a.db.NewSelect().Model((*types.User)(nil))).Count(ctx)
	if err != nil {
		return nil, 0, err
	}

	pageSel := applyConds(a.db.NewSelect().
		Model((*types.User)(nil)).
		Column("id", "name", "email", "whatsapp_number", "dojo", "role").
		OrderExpr("id ASC").
		Limit(size).
		Offset(offset))

	var users []types.User
	if err := pageSel.Scan(ctx, &users); err != nil {
		return nil, 0, err
	}

	summaries := make([]MemberSummary, 0, len(users))
	for i := range users {
		summaries = append(summaries, memberSummaryFromUser(&users[i]))
	}
	return summaries, int64(total), nil
}
