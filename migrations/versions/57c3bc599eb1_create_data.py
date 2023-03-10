"""create data

Revision ID: 57c3bc599eb1
Revises: 
Create Date: 2023-03-01 22:32:45.842595

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '57c3bc599eb1'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('obat', schema=None) as batch_op:
        batch_op.add_column(sa.Column('kondisi', sa.String(length=80), nullable=False))

    with op.batch_alter_table('suplier', schema=None) as batch_op:
        batch_op.alter_column('alamat',
               existing_type=mysql.TEXT(),
               nullable=False)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('suplier', schema=None) as batch_op:
        batch_op.alter_column('alamat',
               existing_type=mysql.TEXT(),
               nullable=True)

    with op.batch_alter_table('obat', schema=None) as batch_op:
        batch_op.drop_column('kondisi')

    # ### end Alembic commands ###
