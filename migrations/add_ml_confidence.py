"""Add ml_confidence to traffic_logs

Revision ID: 1a2b3c4d5e6f
Revises: 
Create Date: 2023-11-15 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '1a2b3c4d5e6f'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    # Add ml_confidence column to traffic_logs table
    op.add_column('traffic_logs', 
                 sa.Column('ml_confidence', sa.Float(), nullable=True))

def downgrade():
    # Remove ml_confidence column from traffic_logs table
    op.drop_column('traffic_logs', 'ml_confidence')
